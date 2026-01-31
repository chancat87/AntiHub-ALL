import tokenManager from '../auth/token_manager.js';
import config, { getApiEndpoint, getEndpointCount } from '../config/config.js';

/**
 * 生成助手响应
 * @param {Object} requestBody - 请求体
 * @param {Function} callback - 回调函数
 * @param {number} endpointIndex - 当前使用的API端点索引（用于403重试）
 * @param {string|null} firstError403Type - 第一次403错误的类型（用于决定是否禁用账号）
 */
export async function generateAssistantResponse(requestBody, callback, endpointIndex = 0, firstError403Type = null) {
  const token = await tokenManager.getToken();
  
  if (!token) {
    throw new Error('没有可用的token，请运行 npm run login 获取token');
  }
  
  // 获取当前端点配置
  const endpoint = getApiEndpoint(endpointIndex);
  const url = endpoint.url;
  
  const requestHeaders = {
    'Host': endpoint.host,
    'User-Agent': config.api.userAgent,
    'Authorization': `Bearer ${token.access_token}`,
    'Content-Type': 'application/json',
    'Accept': 'text/event-stream',
    'Accept-Encoding': 'gzip'
  };
  
  let response;
  
  try {
    // 创建 AbortController 用于超时控制
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, 600000); // 10分钟超时
    
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: requestHeaders,
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }
    
    if (!response.ok) {
      const responseText = await response.text();

      if (response.status === 429) {
        // 上游端点级限流，优先切换端点重试
        const nextEndpointIndex = endpointIndex + 1;
        const totalEndpoints = getEndpointCount();

        if (nextEndpointIndex < totalEndpoints) {
          console.log(`[429错误] 端点[${endpointIndex}]返回429，尝试切换到端点[${nextEndpointIndex}]`);
          return await generateAssistantResponse(requestBody, callback, nextEndpointIndex, firstError403Type);
        }
      }

      if (response.status === 403) {
        // 判断是否是 "The caller does not have permission" 错误
        const isPermissionDenied = responseText.includes('The caller does not have permission') || responseText.includes('PERMISSION_DENIED');
        
        // 记录第一次403错误的类型（只在第一次请求时记录）
        const currentFirstError403Type = firstError403Type === null
          ? (isPermissionDenied ? 'PERMISSION_DENIED' : 'OTHER_403')
          : firstError403Type;
        
        // 尝试切换端点重试
        const nextEndpointIndex = endpointIndex + 1;
        const totalEndpoints = getEndpointCount();
        
        if (nextEndpointIndex < totalEndpoints) {
          // 还有其他端点可以尝试
          console.log(`[403错误] 端点[${endpointIndex}]返回403，尝试切换到端点[${nextEndpointIndex}]`);
          return await generateAssistantResponse(requestBody, callback, nextEndpointIndex, currentFirstError403Type);
        } else {
          // 所有端点都返回403
          // 只有当第一次错误不是 PERMISSION_DENIED 时才禁用账号
          if (currentFirstError403Type !== 'PERMISSION_DENIED') {
            console.log(`[403错误] 所有${totalEndpoints}个端点都返回403，禁用账号`);
            tokenManager.disableCurrentToken(token);
          } else {
            console.log(`[403错误] 所有${totalEndpoints}个端点都返回403，但第一次错误是PERMISSION_DENIED，不禁用账号`);
          }
          throw new Error(`该账号没有使用权限。错误详情: ${responseText}`);
        }
      }
      throw new Error(`API请求失败 (${response.status}): ${responseText}`);
    }
    
  } catch (error) {
    throw error;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let reasoningContent = ''; // 累积 reasoning_content
  let toolCalls = [];
  let sseBuffer = '';
  let parseErrorCount = 0;
  const MAX_SSE_BUFFER_SIZE = 1024 * 1024; // 1MB，防止极端情况下无换行导致内存无界增长

  const processSseLine = (line) => {
    const trimmedLine = typeof line === 'string' ? line.trim() : '';
    if (!trimmedLine.startsWith('data:')) return;

    const jsonStr = trimmedLine.slice('data:'.length).trim();
    if (!jsonStr || jsonStr === '[DONE]') return;

    try {
      const data = JSON.parse(jsonStr);

      const parts = data.response?.candidates?.[0]?.content?.parts;
      if (parts) {
        for (const part of parts) {
          if (part.thought === true) {
            // Gemini 的思考内容转换为 OpenAI 兼容的 reasoning_content 格式
            reasoningContent += part.text || '';
            callback({ type: 'reasoning', content: part.text || '' });
          } else if (part.text !== undefined) {
            // 过滤掉空的非thought文本
            if (part.text.trim() === '') {
              continue;
            }
            callback({ type: 'text', content: part.text });
          } else if (part.functionCall) {
            toolCalls.push({
              id: part.functionCall.id,
              type: 'function',
              function: {
                name: part.functionCall.name,
                arguments: JSON.stringify(part.functionCall.args)
              }
            });
          }
        }
      }

      // 当遇到 finishReason 时，发送所有收集的工具调用
      if (data.response?.candidates?.[0]?.finishReason && toolCalls.length > 0) {
        callback({ type: 'tool_calls', tool_calls: toolCalls });
        toolCalls = [];
      }
    } catch (e) {
      // 理论上这里不应该频繁发生（我们已经做了跨 chunk 的按行缓冲）。
      parseErrorCount++;
    }
  };

  let chunkCount = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    
    const chunk = decoder.decode(value, { stream: true });
    chunkCount++;
    sseBuffer += chunk;

    if (sseBuffer.length > MAX_SSE_BUFFER_SIZE) {
      // 只保留尾部，避免内存爆炸；并尽量保留最后一个未完整的行
      sseBuffer = sseBuffer.slice(-MAX_SSE_BUFFER_SIZE);
      console.debug('[SSE] buffer truncated (too large)');
    }

    let newlineIndex;
    while ((newlineIndex = sseBuffer.indexOf('\n')) !== -1) {
      const line = sseBuffer.slice(0, newlineIndex);
      sseBuffer = sseBuffer.slice(newlineIndex + 1);
      processSseLine(line);
    }
  }

  // flush decoder internal buffer (multi-byte chars)
  sseBuffer += decoder.decode();
  let newlineIndex;
  while ((newlineIndex = sseBuffer.indexOf('\n')) !== -1) {
    const line = sseBuffer.slice(0, newlineIndex);
    sseBuffer = sseBuffer.slice(newlineIndex + 1);
    processSseLine(line);
  }
  if (sseBuffer.trim()) {
    processSseLine(sseBuffer);
  }
  if (parseErrorCount > 0) {
    console.debug(`[SSE] ignored ${parseErrorCount} JSON parse errors`);
  }
}

/**
 * 获取可用模型列表
 * @param {number} endpointIndex - 当前使用的API端点索引（用于403重试）
 * @param {string|null} firstError403Type - 第一次403错误的类型（用于决定是否禁用账号）
 */
export async function getAvailableModels(endpointIndex = 0, firstError403Type = null) {
  const token = await tokenManager.getToken();
  
  if (!token) {
    throw new Error('没有可用的token，请运行 npm run login 获取token');
  }
  
  // 获取当前端点配置
  const endpoint = getApiEndpoint(endpointIndex);
  const modelsUrl = endpoint.modelsUrl;
  
  const requestHeaders = {
    'Host': endpoint.host,
    'User-Agent': config.api.userAgent,
    'Authorization': `Bearer ${token.access_token}`,
    'Content-Type': 'application/json',
    'Accept-Encoding': 'gzip'
  };
  const requestBody = {};
  
  let response;
  let data;
  
  try {
    response = await fetch(modelsUrl, {
      method: 'POST',
      headers: requestHeaders,
      body: JSON.stringify(requestBody)
    });
    
    if (response.status === 403) {
      const responseText = await response.text();
      
      // 判断是否是 "The caller does not have permission" 错误
      const isPermissionDenied = responseText.includes('The caller does not have permission') || responseText.includes('PERMISSION_DENIED');
      
      // 记录第一次403错误的类型（只在第一次请求时记录）
      const currentFirstError403Type = firstError403Type === null
        ? (isPermissionDenied ? 'PERMISSION_DENIED' : 'OTHER_403')
        : firstError403Type;
      
      // 尝试切换端点重试
      const nextEndpointIndex = endpointIndex + 1;
      const totalEndpoints = getEndpointCount();
      
      if (nextEndpointIndex < totalEndpoints) {
        console.log(`[获取模型列表-403错误] 端点[${endpointIndex}]返回403，尝试切换到端点[${nextEndpointIndex}]`);
        return await getAvailableModels(nextEndpointIndex, currentFirstError403Type);
      } else {
        // 所有端点都返回403
        // 只有当第一次错误不是 PERMISSION_DENIED 时才禁用账号
        if (currentFirstError403Type !== 'PERMISSION_DENIED') {
          console.log(`[获取模型列表-403错误] 所有${totalEndpoints}个端点都返回403，禁用账号`);
          tokenManager.disableCurrentToken(token);
        } else {
          console.log(`[获取模型列表-403错误] 所有${totalEndpoints}个端点都返回403，但第一次错误是PERMISSION_DENIED，不禁用账号`);
        }
        throw new Error(`获取模型列表失败: 所有端点都返回403`);
      }
    }

    if (response.status === 429) {
      // 上游端点级限流，优先切换端点重试
      const nextEndpointIndex = endpointIndex + 1;
      const totalEndpoints = getEndpointCount();

      if (nextEndpointIndex < totalEndpoints) {
        console.log(`[获取模型列表-429错误] 端点[${endpointIndex}]返回429，尝试切换到端点[${nextEndpointIndex}]`);
        return await getAvailableModels(nextEndpointIndex, firstError403Type);
      }
    }

    data = await response.json();

    if (!response.ok) {
      throw new Error(`获取模型列表失败 (${response.status}): ${JSON.stringify(data)}`);
    }
    
  } catch (error) {
    throw error;
  }
  
  const models = data?.models || {};
  return {
    object: 'list',
    data: Object.keys(models).map(id => ({
      id,
      object: 'model',
      created: Math.floor(Date.now() / 1000),
      owned_by: 'google'
    }))
  };
}

/**
 * 生成图片
 * @param {Object} requestBody - 请求体
 * @param {number} endpointIndex - 当前使用的API端点索引（用于403重试）
 * @param {string|null} firstError403Type - 第一次403错误的类型（用于决定是否禁用账号）
 * @returns {Promise<Object>} 图片生成响应
 */
export async function generateImage(requestBody, endpointIndex = 0, firstError403Type = null) {
  const token = await tokenManager.getToken();
  
  if (!token) {
    throw new Error('没有可用的token，请运行 npm run login 获取token');
  }
  
  // 获取当前端点配置
  const endpoint = getApiEndpoint(endpointIndex);
  const url = endpoint.imageUrl;
  
  const requestHeaders = {
    'Host': endpoint.host,
    'User-Agent': config.api.userAgent,
    'Authorization': `Bearer ${token.access_token}`,
    'Content-Type': 'application/json',
    'Accept-Encoding': 'gzip'
  };
  
  let response;
  
  try {
    // 创建 AbortController 用于超时控制
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, 600000); // 10分钟超时
    
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: requestHeaders,
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }
    
    if (!response.ok) {
      const responseText = await response.text();

      if (response.status === 429) {
        // 上游端点级限流，优先切换端点重试
        const nextEndpointIndex = endpointIndex + 1;
        const totalEndpoints = getEndpointCount();

        if (nextEndpointIndex < totalEndpoints) {
          console.log(`[图片生成-429错误] 端点[${endpointIndex}]返回429，尝试切换到端点[${nextEndpointIndex}]`);
          return await generateImage(requestBody, nextEndpointIndex, firstError403Type);
        }
      }

      if (response.status === 403) {
        // 判断是否是 "The caller does not have permission" 错误
        const isPermissionDenied = responseText.includes('The caller does not have permission') || responseText.includes('PERMISSION_DENIED');
        
        // 记录第一次403错误的类型（只在第一次请求时记录）
        const currentFirstError403Type = firstError403Type === null
          ? (isPermissionDenied ? 'PERMISSION_DENIED' : 'OTHER_403')
          : firstError403Type;
        
        // 尝试切换端点重试
        const nextEndpointIndex = endpointIndex + 1;
        const totalEndpoints = getEndpointCount();
        
        if (nextEndpointIndex < totalEndpoints) {
          // 还有其他端点可以尝试
          console.log(`[图片生成-403错误] 端点[${endpointIndex}]返回403，尝试切换到端点[${nextEndpointIndex}]`);
          return await generateImage(requestBody, nextEndpointIndex, currentFirstError403Type);
        } else {
          // 所有端点都返回403
          // 只有当第一次错误不是 PERMISSION_DENIED 时才禁用账号
          if (currentFirstError403Type !== 'PERMISSION_DENIED') {
            console.log(`[图片生成-403错误] 所有${totalEndpoints}个端点都返回403，禁用账号`);
            tokenManager.disableCurrentToken(token);
          } else {
            console.log(`[图片生成-403错误] 所有${totalEndpoints}个端点都返回403，但第一次错误是PERMISSION_DENIED，不禁用账号`);
          }
          throw new Error(`该账号没有使用权限。错误详情: ${responseText}`);
        }
      }
      throw new Error(`API请求失败 (${response.status}): ${responseText}`);
    }
    
  } catch (error) {
    throw error;
  }

  // 解析响应 (非流式JSON格式)
  const responseData = await response.json();
  
  // 直接从响应中提取数据
  const candidates = responseData.candidates || [];
  const collectedParts = candidates[0]?.content?.parts || [];
  const lastFinishReason = candidates[0]?.finishReason || 'STOP';

  // 构造标准的 Gemini 响应格式
  const data = {
    candidates: [
      {
        content: {
          parts: collectedParts,
          role: 'model'
        },
        finishReason: lastFinishReason
      }
    ]
  };
  return data;
}
