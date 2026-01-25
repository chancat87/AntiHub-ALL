import database from '../src/db/database.js';
import logger from '../src/utils/logger.js';
import quotaService from '../src/services/quota.service.compat.js';
import oauthService from '../src/services/oauth.service.js';
import accountService from '../src/services/account.service.js';
import config from '../src/config/config.js';
import fs from 'fs';

// 读取配置文件
let dbConfig;
try {
  const configFile = fs.readFileSync('./config.json', 'utf8');
  const configData = JSON.parse(configFile);
  dbConfig = configData.database;
} catch (error) {
  logger.error('读取配置文件失败:', error.message);
  process.exit(1);
}

/**
 * 从API获取账号的配额信息（使用指定的projectId）
 * @param {string} accessToken - 访问令牌
 * @param {string} projectId - 项目ID
 * @returns {Promise<Object>} 模型配额信息
 */
async function fetchQuotaFromAPI(accessToken, projectId) {
  try {
    const requestHeaders = {
      'Host': config.api.host,
      'User-Agent': config.api.userAgent,
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'Accept-Encoding': 'gzip'
    };

    // 构建请求体，包含projectId
    const requestBody = {
      project: projectId
    };

    const response = await fetch(config.api.modelsUrl, {
      method: 'POST',
      headers: requestHeaders,
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      const responseText = await response.text();
      throw new Error(`API请求失败 (${response.status}): ${responseText}`);
    }

    const data = await response.json();
    return data.models || {};
  } catch (error) {
    throw error;
  }
}

/**
 * 合并两个projectId的配额信息，配额叠加
 * @param {Object} models1 - 第一个projectId的模型配额
 * @param {Object} models2 - 第二个projectId的模型配额
 * @returns {Object} 合并后的模型配额
 */
function mergeQuotas(models1, models2) {
  const merged = { ...models1 };
  
  for (const [modelName, modelInfo] of Object.entries(models2)) {
    if (!merged[modelName]) {
      // 如果第一个projectId没有这个模型，直接使用第二个的
      merged[modelName] = modelInfo;
    } else if (modelInfo.quotaInfo && merged[modelName].quotaInfo) {
      // 如果两个都有配额信息，配额直接叠加（无上限）
      const quota1 = merged[modelName].quotaInfo.remainingFraction || 0;
      const quota2 = modelInfo.quotaInfo.remainingFraction || 0;
      const sumQuota = quota1 + quota2; // 直接叠加，无上限
      
      // 更新配额值
      merged[modelName] = {
        ...merged[modelName],
        quotaInfo: {
          ...merged[modelName].quotaInfo,
          remainingFraction: sumQuota
        }
      };
      
      // 如果有重置时间，使用较晚的那个
      if (modelInfo.quotaInfo.resetTime && merged[modelName].quotaInfo.resetTime) {
        const resetTime1 = new Date(merged[modelName].quotaInfo.resetTime);
        const resetTime2 = new Date(modelInfo.quotaInfo.resetTime);
        if (resetTime2 > resetTime1) {
          merged[modelName].quotaInfo.resetTime = modelInfo.quotaInfo.resetTime;
        }
      }
    }
  }
  
  return merged;
}

/**
 * 更新所有用户账号的配额信息
 */
async function updateAllUserQuotas() {
  try {
    // 初始化数据库连接
    database.initialize(dbConfig);
    logger.info('数据库连接已初始化');
    
    logger.info('开始同步所有账号的配额信息...\n');
    
    // 获取所有启用的账号
    const result = await database.query(
      'SELECT cookie_id, user_id, is_shared, access_token, refresh_token, expires_at, project_id_0 FROM accounts WHERE status = 1 ORDER BY created_at ASC'
    );
    
    const accounts = result.rows;
    logger.info(`找到 ${accounts.length} 个启用的账号\n`);
    
    let successCount = 0;
    let failedCount = 0;
    let tokenRefreshCount = 0;
    const results = [];
    
    for (let i = 0; i < accounts.length; i++) {
      const account = accounts[i];
      logger.info(`[${i + 1}/${accounts.length}] 处理账号: ${account.cookie_id}`);
      logger.info(`  类型: ${account.is_shared === 1 ? '共享' : '专属'}`);
      
      try {
        // 检查token是否过期
        let accessToken = account.access_token;
        if (accountService.isTokenExpired(account)) {
          logger.info(`  Token已过期，正在刷新...`);
          try {
            const tokenData = await oauthService.refreshAccessToken(account.refresh_token);
            const expires_at = Date.now() + (tokenData.expires_in * 1000);
            await accountService.updateAccountToken(account.cookie_id, tokenData.access_token, expires_at);
            accessToken = tokenData.access_token;
            tokenRefreshCount++;
            logger.info(`  ✓ Token刷新成功`);
          } catch (refreshError) {
            logger.error(`  ✗ Token刷新失败: ${refreshError.message}`);
            if (refreshError.isInvalidGrant) {
              logger.error(`  账号需要重新授权，已禁用`);
              await accountService.updateAccountStatus(account.cookie_id, 0);
            }
            failedCount++;
            results.push({
              cookie_id: account.cookie_id,
              success: false,
              error: 'Token刷新失败'
            });
            continue;
          }
        }
        
        // 从API获取配额信息（使用两个projectId）
        logger.info(`  正在从API获取配额信息...`);
        
        let modelsData = {};
        
        // 使用 project_id_0 获取配额（即使为空也尝试）
        try {
          const pid0 = account.project_id_0 || '';
          logger.info(`    使用 project_id_0: ${pid0 || '(空)'}`);
          const models0 = await fetchQuotaFromAPI(accessToken, pid0);
          modelsData = models0;
          logger.info(`    ✓ project_id_0 获取成功: ${Object.keys(models0).length} 个模型`);
        } catch (error) {
          logger.warn(`    ✗ project_id_0 获取失败: ${error.message}`);
        }
        
        if (Object.keys(modelsData).length === 0) {
          throw new Error('无法获取配额信息');
        }
        
        // 更新到数据库
        const updatedQuotas = await quotaService.updateQuotasFromModels(account.cookie_id, modelsData);
        
        logger.info(`  ✓ 配额已更新: ${updatedQuotas.length} 个模型`);
        
        // 显示配额详情
        for (const quota of updatedQuotas) {
          const quotaPercent = (quota.quota * 100).toFixed(2);
          const statusText = quota.status === 1 ? '可用' : '不可用';
          logger.info(`    - ${quota.model_name}: ${quotaPercent}% (${statusText})`);
        }
        
        successCount++;
        results.push({
          cookie_id: account.cookie_id,
          success: true,
          models_count: updatedQuotas.length
        });
        
        // 如果是共享账号，更新用户共享配额池
        if (account.is_shared === 1) {
          logger.info(`  正在更新用户共享配额池...`);
          const uniqueModels = new Set();
          for (const quota of updatedQuotas) {
            uniqueModels.add(quota.model_name);
          }
          
          for (const modelName of uniqueModels) {
            try {
              await quotaService.updateUserSharedQuotaMax(account.user_id, modelName);
            } catch (error) {
              logger.warn(`    警告: 更新 ${modelName} 的共享配额池失败: ${error.message}`);
            }
          }
          logger.info(`  ✓ 共享配额池已更新`);
        }
        
      } catch (error) {
        logger.error(`  ✗ 处理失败: ${error.message}`);
        failedCount++;
        results.push({
          cookie_id: account.cookie_id,
          success: false,
          error: error.message
        });
      }
      
      logger.info(''); // 空行分隔
    }
    
    logger.info('========== 同步完成 ==========');
    logger.info(`总账号数: ${accounts.length}`);
    logger.info(`成功: ${successCount}`);
    logger.info(`失败: ${failedCount}`);
    logger.info(`Token刷新: ${tokenRefreshCount}`);
    logger.info('==============================\n');
    
    // 显示失败的账号
    if (failedCount > 0) {
      logger.info('失败的账号:');
      for (const result of results) {
        if (!result.success) {
          logger.info(`  - ${result.cookie_id}: ${result.error}`);
        }
      }
      logger.info('');
    }
    
    
  } catch (error) {
    logger.error('同步配额失败:', error.message);
    throw error;
  } finally {
    // 关闭数据库连接
    await database.close();
  }
}

// 运行脚本
updateAllUserQuotas()
  .then(() => {
    logger.info('\n脚本执行成功');
    process.exit(0);
  })
  .catch((error) => {
    logger.error('\n脚本执行失败:', error);
    process.exit(1);
  });
