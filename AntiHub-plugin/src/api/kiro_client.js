import https from 'https';
import crypto from 'crypto';
import logger from '../utils/logger.js';
import kiroService from '../services/kiro.service.js';
import kiroAccountService from '../services/kiro_account.service.js';
import kiroConsumptionService from '../services/kiro_consumption.service.js';
import kiroSubscriptionModelService from '../services/kiro_subscription_model.service.js';

/**
 * Kiro API 客户端
 * 处理CodeWhisperer API调用和流式响应
 */
class KiroClient {
  /**
   * 获取可用的Kiro账号（带token刷新）
   * @param {string} user_id - 用户ID
   * @param {Array} excludeAccountIds - 要排除的账号ID列表（用于重试时排除已失败的账号）
   * @returns {Promise<Object>} 账号对象
   */
  async getAvailableAccount(user_id, excludeAccountIds = [], modelId = null) {
    let accounts = await kiroAccountService.getAvailableAccounts(user_id);
    
    // 排除已经尝试失败的账号
    if (excludeAccountIds.length > 0) {
      accounts = accounts.filter(acc => !excludeAccountIds.includes(acc.account_id));
    }
    
    // 按订阅层规则过滤可用账号（未配置规则时默认放行，兼容旧行为）
    if (modelId) {
      const filtered = await kiroSubscriptionModelService.filterAccountsByModel(accounts, modelId);
      if (accounts.length > 0 && filtered.length === 0) {
        const subs = Array.from(new Set(accounts.map(a => a.subscription).filter(Boolean)));
        throw new Error(`没有可用的Kiro账号可用于模型: ${modelId}（当前账号订阅层: ${subs.join(', ') || 'unknown'}）`);
      }
      accounts = filtered;
    }

    if (accounts.length === 0) {
      throw new Error('没有可用的Kiro账号，请先添加账号');
    }

    // 随机选择一个账号
    const account = accounts[Math.floor(Math.random() * accounts.length)];
    
    // 检查token是否过期
    if (kiroAccountService.isTokenExpired(account)) {
      logger.info(`Kiro账号token已过期，正在刷新: account_id=${account.account_id}`);
      
      try {
        const tokenData = await kiroService.refreshToken({
          machineid: account.machineid,
          auth: account.auth_method,
          refreshToken: account.refresh_token,
          clientId: account.client_id,
          clientSecret: account.client_secret
        });
        
        const expires_at = Date.now() + (tokenData.expires_in * 1000);
        await kiroAccountService.updateAccountToken(
          account.account_id,
          tokenData.access_token,
          expires_at,
          tokenData.profile_arn
        );
        
        account.access_token = tokenData.access_token;
        account.expires_at = expires_at;
      } catch (refreshError) {
        // 刷新token失败，标记账号需要重新授权
        logger.error(`Kiro账号刷新token失败，标记需要重新授权: account_id=${account.account_id}, error=${refreshError.message}`);
        await kiroAccountService.markAccountNeedRefresh(account.account_id);
        
        // 尝试获取下一个可用账号
        const newExcludeList = [...excludeAccountIds, account.account_id];
        return this.getAvailableAccount(user_id, newExcludeList, modelId);
      }
    }

    return account;
  }

  /**
   * 生成响应（流式）
   * @param {Array} messages - OpenAI格式消息
   * @param {string} model - 模型名称
   * @param {Function} callback - 回调函数
   * @param {string} user_id - 用户ID
   * @param {Object} options - 其他选项
   * @param {Object|null} accountOverride - 可选：指定账号（避免重复选择）
   */
  async generateResponse(messages, model, callback, user_id, options = {}, accountOverride = null) {
    const account = accountOverride || await this.getAvailableAccount(user_id, [], model);
    const requestId = crypto.randomUUID().substring(0, 8);
    
    logger.info(`[${requestId}] 开始Kiro请求: model=${model}, user_id=${user_id}, account_id=${account.account_id}`);

    // 转换请求格式
    const cwRequest = kiroService.convertToCodeWhispererRequest(messages, model, options);
    const requestBody = JSON.stringify(cwRequest);

    return new Promise((resolve, reject) => {
      const headers = kiroService.getCodeWhispererHeaders(account.access_token, account.machineid);
      headers['Content-Length'] = Buffer.byteLength(requestBody);

      const reqOptions = {
        hostname: 'q.us-east-1.amazonaws.com',
        path: '/generateAssistantResponse',
        method: 'POST',
        headers
      };

      const req = https.request(reqOptions, (res) => {
        logger.info(`[${requestId}] 收到响应: status=${res.statusCode}`);

        if (res.statusCode !== 200) {
          let errorBody = '';
          res.on('data', chunk => errorBody += chunk);
          res.on('end', () => {
            logger.error(`[${requestId}] API错误: ${res.statusCode} - ${errorBody}`);
            
            // 402 或 403 错误时自动禁用账号
            if (res.statusCode === 402 || res.statusCode === 403) {
              kiroAccountService.updateAccountStatus(account.account_id, 0);
              logger.warn(`Kiro账号已禁用(${res.statusCode}): account_id=${account.account_id}`);
            }
            
            reject(new Error(`错误: ${res.statusCode} ${errorBody}`));
          });
          return;
        }

        // 处理流式响应，传递账号和模型信息
        const contextInfo = {
          user_id,
          account_id: account.account_id,
          model_id: model,
          is_shared: account.is_shared
        };
        
        this.handleStreamResponse(res, callback, requestId, contextInfo)
          .then(() => {
            logger.info(`[${requestId}] 请求完成`);
            resolve();
          })
          .catch(reject);
      });

      req.on('error', (error) => {
        logger.error(`[${requestId}] 请求异常:`, error.message);
        reject(error);
      });

      req.write(requestBody);
      req.end();
    });
  }

  /**
   * 处理流式响应
   * @param {Object} response - HTTP响应对象
   * @param {Function} callback - 回调函数
   * @param {string} requestId - 请求ID
   * @param {Object} contextInfo - 上下文信息（user_id, account_id, model_id, is_shared）
   */
  async handleStreamResponse(response, callback, requestId, contextInfo) {
    let buffer = Buffer.alloc(0);
    let messageCount = 0;
    // 跟踪工具调用：toolUseId -> index 的映射
    const toolCallIndexMap = new Map();
    // 使用对象包装计数器，这样可以在函数间共享引用
    const indexCounter = { value: 0 };

    return new Promise((resolve, reject) => {
      response.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);

        // 解析事件流消息
        while (buffer.length >= 16) {
          const totalLength = buffer.readUInt32BE(0);
          
          if (totalLength < 16 || totalLength > 16 * 1024 * 1024) {
            buffer = buffer.slice(1);
            continue;
          }

          if (buffer.length < totalLength) {
            break;
          }

          const messageData = buffer.slice(0, totalLength);
          buffer = buffer.slice(totalLength);

          try {
            const message = this.parseSingleMessage(messageData);
            if (message) {
              messageCount++;
              this.processMessage(message, callback, requestId, contextInfo, toolCallIndexMap, indexCounter);
            }
          } catch (error) {
            logger.warn(`[${requestId}] 消息解析失败:`, error.message);
          }
        }
      });

      response.on('end', () => {
        resolve();
      });

      response.on('error', (error) => {
        reject(error);
      });
    });
  }

  /**
   * 解析单条消息
   * @param {Buffer} data - 消息数据
   * @returns {Object|null} 解析后的消息
   */
  parseSingleMessage(data) {
    if (data.length < 16) return null;

    const totalLength = data.readUInt32BE(0);
    const headerLength = data.readUInt32BE(4);

    if (totalLength !== data.length) {
      throw new Error(`长度不匹配: expected ${totalLength}, got ${data.length}`);
    }

    const payloadStart = 12 + headerLength;
    const payloadEnd = totalLength - 4;

    if (payloadStart > payloadEnd || payloadEnd > data.length) {
      throw new Error(`Payload边界错误`);
    }

    const payloadData = data.slice(payloadStart, payloadEnd);

    if (payloadData.length === 0) {
      return null;
    }

    try {
      const payloadStr = payloadData.toString('utf-8');
      const payload = JSON.parse(payloadStr);
      return payload;
    } catch (error) {
      logger.debug('Payload解析失败，可能是非JSON数据');
      return null;
    }
  }

  /**
   * 处理消息并调用回调
   * @param {Object} message - 消息对象
   * @param {Function} callback - 回调函数
   * @param {string} requestId - 请求ID
   * @param {Object} contextInfo - 上下文信息（user_id, account_id, model_id, is_shared）
   * @param {Map} toolCallIndexMap - 工具调用ID到索引的映射
   * @param {Object} indexCounter - 索引计数器对象 { value: number }
   */
  processMessage(message, callback, requestId, contextInfo, toolCallIndexMap, indexCounter) {
    // 处理文本内容
    if (message.content) {
      callback({ type: 'text', content: message.content });
    }

    // 处理 Anthropic 格式的工具调用（标准格式）
    if (message.name && message.toolUseId) {
      // Anthropic 格式: { name: "WebSearch", toolUseId: "xxx", input: {...} }
      // 转换为 OpenAI 流式格式
      
      // 获取或分配工具调用索引
      let toolCallIndex;
      if (toolCallIndexMap.has(message.toolUseId)) {
        toolCallIndex = toolCallIndexMap.get(message.toolUseId);
      } else {
        toolCallIndex = indexCounter.value;
        toolCallIndexMap.set(message.toolUseId, toolCallIndex);
        indexCounter.value++; // 递增计数器
      }
      
      const toolCall = {
        index: toolCallIndex,
        id: message.toolUseId,
        type: 'function',
        function: {
          name: message.name,
          arguments: ''  // 流式响应中先发送空字符串
        }
      };
      callback({ type: 'tool_call_start', tool_calls: [toolCall] });
    }

    // 处理工具调用的参数（流式传输）
    if (message.input && message.toolUseId) {
      // 获取工具调用索引
      const toolCallIndex = toolCallIndexMap.get(message.toolUseId);
      if (toolCallIndex === undefined) {
        logger.warn(`[${requestId}] 收到未知工具调用的input: toolUseId=${message.toolUseId}`);
        return;
      }
      
      // 将 input 对象转换为 JSON 字符串，模拟流式传输
      const args = typeof message.input === 'string' ? message.input : JSON.stringify(message.input);
      callback({
        type: 'tool_call_delta',
        tool_call_index: toolCallIndex,
        tool_call_id: message.toolUseId,
        delta: args
      });
    }

    // 处理 CodeWhisperer 的工具调用格式（兼容旧格式）
    if (message.codeQuery) {
      const toolCall = {
        id: message.codeQuery.codeQueryId || crypto.randomUUID(),
        type: 'function',
        function: {
          name: message.codeQuery.programmingLanguage?.languageName || 'unknown',
          arguments: JSON.stringify(message.codeQuery)
        }
      };
      callback({ type: 'tool_calls', tool_calls: [toolCall] });
    }

    // 处理usage消息（记录消费日志并更新账号余额）
    if (message.usage && typeof message.usage === 'number' && contextInfo) {
      logger.info(`[${requestId}] 检测到usage: ${message.usage}, 准备记录消费日志并更新余额`);
      
      // 异步记录消费日志并更新余额，不阻塞响应流
      this.logConsumptionAndUpdateBalance(requestId, contextInfo, message.usage)
        .catch(error => {
          logger.error(`[${requestId}] 记录消费日志或更新余额失败:`, error.message);
        });
    }
  }

  /**
   * 记录消费日志并更新账号余额
   * @param {string} requestId - 请求ID
   * @param {Object} contextInfo - 上下文信息
   * @param {number} creditUsed - 消耗的credit
   */
  async logConsumptionAndUpdateBalance(requestId, contextInfo, creditUsed) {
    // 1. 记录消费日志
    await kiroConsumptionService.logConsumption({
      user_id: contextInfo.user_id,
      account_id: contextInfo.account_id,
      model_id: contextInfo.model_id,
      credit_used: creditUsed,
      is_shared: contextInfo.is_shared
    });

    // 2. 获取账号信息
    const account = await kiroAccountService.getAccountById(contextInfo.account_id);
    if (!account) {
      logger.warn(`[${requestId}] 账号不存在，无法更新余额: account_id=${contextInfo.account_id}`);
      return;
    }

    // 3. 从上游获取最新的使用量信息
    try {
      logger.info(`[${requestId}] 从上游获取最新余额信息: account_id=${contextInfo.account_id}`);
      
      // 检查token是否过期，如果过期则刷新
      let accessToken = account.access_token;
      if (kiroAccountService.isTokenExpired(account)) {
        logger.info(`[${requestId}] Token已过期，正在刷新`);
        try {
          const tokenData = await kiroService.refreshToken({
            machineid: account.machineid,
            auth: account.auth_method,
            refreshToken: account.refresh_token,
            clientId: account.client_id,
            clientSecret: account.client_secret
          });
          
          const expires_at = Date.now() + (tokenData.expires_in * 1000);
          await kiroAccountService.updateAccountToken(
            account.account_id,
            tokenData.access_token,
            expires_at,
            tokenData.profile_arn
          );
          
          accessToken = tokenData.access_token;
        } catch (refreshError) {
          // 刷新token失败，标记账号需要重新授权
          logger.error(`[${requestId}] 刷新token失败，标记账号需要重新授权: account_id=${account.account_id}, error=${refreshError.message}`);
          await kiroAccountService.markAccountNeedRefresh(account.account_id);
          // 这里不抛出错误，因为消费日志已经记录成功，只是无法更新余额
          return;
        }
      }

      // 调用上游API获取最新使用量
      const usageLimitsData = await kiroService.getUsageLimits(
        accessToken,
        account.profile_arn,
        account.machineid
      );

      // 4. 更新数据库中的余额信息（包含免费试用和bonus信息）
      await kiroAccountService.updateAccountUsage(contextInfo.account_id, {
        email: usageLimitsData.email,
        userid: usageLimitsData.userid,
        subscription: usageLimitsData.subscription,
        current_usage: usageLimitsData.current_usage,
        reset_date: usageLimitsData.reset_date,
        usage_limit: usageLimitsData.usage_limit,
        // 免费试用信息（free_trial_status 现在是字符串：ACTIVE/EXPIRED/null）
        free_trial_status: usageLimitsData.free_trial_status,
        free_trial_usage: usageLimitsData.free_trial_usage,
        free_trial_expiry: usageLimitsData.free_trial_expiry,
        free_trial_limit: usageLimitsData.free_trial_limit,
        // bonus信息
        bonus_usage: usageLimitsData.bonus_usage,
        bonus_limit: usageLimitsData.bonus_limit,
        bonus_available: usageLimitsData.bonus_available,
        bonus_details: usageLimitsData.bonus_details
      });

      logger.info(`[${requestId}] 余额已更新: account_id=${contextInfo.account_id}, current_usage=${usageLimitsData.current_usage}`);
    } catch (error) {
      logger.error(`[${requestId}] 更新余额失败:`, error.message);
      // 不抛出错误，因为消费日志已经记录成功
    }
  }

  /**
   * 获取可用模型列表
   * @returns {Object} 模型列表
   */
  getAvailableModels() {
    const models = kiroService.getAvailableModels();
    return {
      object: 'list',
      data: models
    };
  }
}

const kiroClient = new KiroClient();
export default kiroClient;
