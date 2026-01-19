import logger from '../utils/logger.js';
import accountService from './account.service.js';
import config from '../config/config.js';

class ProjectService {
  async listGcpProjects(accessToken) {
    const url = 'https://cloudresourcemanager.googleapis.com/v1/projects';
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const responseText = await response.text();
      throw new Error(`listGcpProjects API request failed (${response.status}): ${responseText}`);
    }

    const data = await response.json();
    return Array.isArray(data?.projects) ? data.projects : [];
  }

  selectDefaultGcpProjectId(projects) {
    if (!Array.isArray(projects) || projects.length === 0) return '';

    const active = projects.find((p) => p && typeof p === 'object' && p.lifecycleState === 'ACTIVE');
    const candidate = active || projects[0];
    const projectId = candidate?.projectId;
    return typeof projectId === 'string' ? projectId.trim() : '';
  }

  getApiEndpoints() {
    return [
      {
        baseUrl: 'https://cloudcode-pa.googleapis.com',
        host: 'cloudcode-pa.googleapis.com',
      },
    ];
  }

  buildRequestHeaders({ accessToken, host }) {
    return {
      Host: host,
      'User-Agent': config.api.userAgent,
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'Accept-Encoding': 'gzip',
    };
  }

  getCodeAssistMetadata() {
    return {
      ideType: 'ANTIGRAVITY',
      platform: 'PLATFORM_UNSPECIFIED',
      pluginType: 'GEMINI',
    };
  }

  extractProjectId(value) {
    if (!value) return '';

    if (typeof value === 'string') {
      return value.trim();
    }

    if (typeof value === 'object') {
      const id = value.id ?? value.projectId ?? value.project_id;
      if (typeof id === 'string') return id.trim();
    }

    return '';
  }

  getDefaultTierId(loadCodeAssistResponse) {
    const fallback = 'legacy-tier';
    const tiers = loadCodeAssistResponse?.allowedTiers;
    if (!Array.isArray(tiers)) return fallback;

    const defaultTier = tiers.find((tier) => tier && typeof tier === 'object' && tier.isDefault);
    const id = defaultTier?.id;
    return typeof id === 'string' && id.trim() ? id.trim() : fallback;
  }

  async sleep(ms) {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  async loadCodeAssist(accessToken) {
    let lastError = null;

    for (const endpoint of this.getApiEndpoints()) {
      try {
        const requestHeaders = this.buildRequestHeaders({ accessToken, host: endpoint.host });
        const response = await fetch(`${endpoint.baseUrl}/v1internal:loadCodeAssist`, {
          method: 'POST',
          headers: requestHeaders,
          body: JSON.stringify({ metadata: this.getCodeAssistMetadata() }),
        });

        if (!response.ok) {
          const responseText = await response.text();
          throw new Error(`API请求失败 (${response.status}): ${responseText}`);
        }

        return await response.json();
      } catch (error) {
        lastError = error;
        logger.warn(`loadCodeAssist 失败，尝试下一个端点: host=${endpoint.host}, error=${error?.message || error}`);
      }
    }

    logger.error('调用loadCodeAssist API失败(所有端点):', lastError?.message || lastError);
    throw lastError || new Error('调用loadCodeAssist API失败');
  }

  async onboardUser(accessToken, tierId = 'legacy-tier') {
    const requestBody = {
      tierId,
      metadata: this.getCodeAssistMetadata(),
    };

    const maxAttempts = 5;
    const retryDelayMs = 2000;
    let lastError = null;

    for (const endpoint of this.getApiEndpoints()) {
      const requestHeaders = this.buildRequestHeaders({ accessToken, host: endpoint.host });
      try {
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
          const response = await fetch(`${endpoint.baseUrl}/v1internal:onboardUser`, {
            method: 'POST',
            headers: requestHeaders,
            body: JSON.stringify(requestBody),
          });

          if (!response.ok) {
            const responseText = await response.text();
            throw new Error(`onboardUser API请求失败 (${response.status}): ${responseText}`);
          }

          const data = await response.json();

          if (!data?.done) {
            logger.info(`onboardUser 未完成，等待重试: host=${endpoint.host}, attempt=${attempt}/${maxAttempts}`);
            await this.sleep(retryDelayMs);
            continue;
          }

          const fromResponse = this.extractProjectId(data?.response?.cloudaicompanionProject);
          const fromTopLevel = this.extractProjectId(data?.cloudaicompanionProject);
          const projectId = fromResponse || fromTopLevel;
          if (projectId) return projectId;

          throw new Error(`onboardUser 返回 done=true 但缺少 project_id: ${JSON.stringify(data).slice(0, 500)}`);
        }
      } catch (error) {
        lastError = error;
        logger.warn(`onboardUser 失败，尝试下一个端点: host=${endpoint.host}, error=${error?.message || error}`);
      }
    }

    throw lastError || new Error('onboardUser 失败');
  }

  /**
   * 处理API响应并更新账号的project_id字段
   * @param {string} cookie_id - Cookie ID
   * @param {string} accessToken - 访问令牌
   * @returns {Promise<Object>} 更新后的账号信息
   */
  async updateAccountProjectIds(cookie_id, accessToken) {
    try {
      // 调用API获取项目信息
      const apiResponse = await this.loadCodeAssist(accessToken);
      
      // 默认值
      let is_restricted = false;
      let ineligible = false;
      
      // 检查 ineligibleTiers 是否存在
      if (apiResponse.ineligibleTiers && apiResponse.ineligibleTiers.length > 0) {
        // 检查是否包含 INELIGIBLE_ACCOUNT
        const hasIneligibleAccount = apiResponse.ineligibleTiers.some(
          tier => tier.reasonCode === 'INELIGIBLE_ACCOUNT'
        );
        
        if (hasIneligibleAccount) {
          // 如果是 INELIGIBLE_ACCOUNT，设置 ineligible=true
          ineligible = true;
        }
        
        // 检查是否包含 UNSUPPORTED_LOCATION
        const hasUnsupportedLocation = apiResponse.ineligibleTiers.some(
          tier => tier.reasonCode === 'UNSUPPORTED_LOCATION'
        );
        
        if (hasUnsupportedLocation) {
          // 如果是 UNSUPPORTED_LOCATION，设置 is_restricted=true
          is_restricted = true;
        }
      }
      
      // 尝试从 loadCodeAssist 获取 project_id；拿不到则走 onboardUser 获取真实 project_id
      let project_id_0 = '';
      if (!is_restricted) {
        project_id_0 = this.extractProjectId(apiResponse?.cloudaicompanionProject);

        if (!project_id_0 && !ineligible) {
          try {
            const tierId = this.getDefaultTierId(apiResponse);
            project_id_0 = await this.onboardUser(accessToken, tierId);
          } catch (error) {
            logger.warn(`onboardUser 获取 project_id 失败: cookie_id=${cookie_id}, error=${error?.message || error}`);
          }
        }
      }
      
      // 判断是否为付费用户：paidTier.id 不包含 'free' 字符串则为付费用户
      // 如果没有paidTier，默认为false（免费用户）
      let paid_tier = false;
      if (apiResponse.paidTier?.id) {
        paid_tier = !apiResponse.paidTier.id.toLowerCase().includes('free');
      }
      
      // 更新数据库
      const updatedAccount = await accountService.updateProjectIds(
        cookie_id,
        project_id_0,
        is_restricted,
        ineligible,
        paid_tier
      );
      
      // 返回更新后的账号信息，并附加paidTier完整对象用于判断
      return {
        ...updatedAccount,
        paidTier: apiResponse.paidTier || null
      };
    } catch (error) {
      throw error;
    }
  }

  /**
   * 批量更新多个账号的project_id
   * @param {Array<Object>} accounts - 账号列表，每个账号包含 cookie_id 和 access_token
   * @returns {Promise<Array>} 更新结果列表
   */
  async batchUpdateProjectIds(accounts) {
    const results = [];
    
    for (const account of accounts) {
      try {
        const result = await this.updateAccountProjectIds(
          account.cookie_id,
          account.access_token
        );
        results.push({
          cookie_id: account.cookie_id,
          success: true,
          data: result
        });
      } catch (error) {
        results.push({
          cookie_id: account.cookie_id,
          success: false,
          error: error.message
        });
      }
    }
    
    return results;
  }
}

const projectService = new ProjectService();
export default projectService;
