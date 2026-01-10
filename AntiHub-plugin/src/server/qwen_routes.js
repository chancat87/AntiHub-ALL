import express from 'express';
import crypto from 'crypto';
import qwenAccountService from '../services/qwen_account.service.js';
import qwenService from '../services/qwen.service.js';
import redisService from '../services/redis.service.js';
import userService from '../services/user.service.js';
import logger from '../utils/logger.js';
import config from '../config/config.js';

const router = express.Router();

/**
 * API Key认证中间件
 */
const authenticateApiKey = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '缺少Authorization请求头' });
  }

  const apiKey = authHeader.slice(7);

  // 管理员Key
  if (apiKey === config.security?.adminApiKey) {
    req.isAdmin = true;
    req.user = { user_id: 'admin', api_key: apiKey };
    return next();
  }

  const user = await userService.validateApiKey(apiKey);
  if (!user) {
    return res.status(401).json({ error: '无效的API Key' });
  }

  req.user = user;
  req.isAdmin = false;
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.isAdmin) {
    return res.status(403).json({ error: '需要管理员权限' });
  }
  next();
};

function toSafeAccount(account) {
  if (!account) return null;
  return {
    account_id: account.account_id,
    user_id: account.user_id,
    is_shared: account.is_shared,
    status: account.status,
    need_refresh: account.need_refresh,
    expires_at: account.expires_at,
    email: account.email,
    account_name: account.account_name,
    resource_url: account.resource_url,
    last_refresh: account.last_refresh,
    created_at: account.created_at,
    updated_at: account.updated_at,
  };
}

const qwenOAuthStateKey = (state) => `qwen_oauth:${state}`;

/**
 * Qwen OAuth（Device Flow）
 * POST /api/qwen/oauth/authorize
 * Body: { is_shared, account_name? }
 */
router.post('/api/qwen/oauth/authorize', authenticateApiKey, async (req, res) => {
  try {
    if (!redisService.isAvailable()) {
      return res.status(503).json({ error: 'Redis不可用，无法使用Qwen OAuth登录' });
    }

    const { is_shared = 0, account_name } = req.body || {};
    if (is_shared !== 0 && is_shared !== 1) {
      return res.status(400).json({ error: 'is_shared必须是0或1' });
    }

    const deviceFlow = await qwenService.initiateDeviceFlow();
    const state = `qwen-${crypto.randomUUID()}`;

    // 这份 state 仅用于我们自己轮询登录状态，不会发给 Qwen。
    const ttlSeconds = Math.min(3600, Math.max(300, deviceFlow.expires_in + 120));
    const stateInfo = {
      provider: 'qwen',
      user_id: req.user.user_id,
      is_shared,
      account_name: typeof account_name === 'string' ? account_name.trim() : '',
      created_at: Date.now(),
      callback_completed: false,
      completed_at: null,
      error: null,
      account_data: null,
    };

    await redisService.set(qwenOAuthStateKey(state), stateInfo, ttlSeconds);

    // 后台轮询，成功后落库（不把 token 写进 Redis，避免泄漏）
    void (async () => {
      try {
        const tokenData = await qwenService.pollForToken({
          device_code: deviceFlow.device_code,
          code_verifier: deviceFlow.code_verifier,
          interval: deviceFlow.interval,
        });

        const expiresAt =
          typeof tokenData.expires_in === 'number'
            ? Date.now() + tokenData.expires_in * 1000
            : null;

        const resourceURL = qwenService.normalizeResourceURL(tokenData.resource_url);
        const email = `qwen-${Date.now()}`;
        const name = stateInfo.account_name || email || 'Qwen Account';

        const account = await qwenAccountService.createAccount({
          user_id: stateInfo.user_id,
          account_name: name,
          is_shared: stateInfo.is_shared,
          access_token: tokenData.access_token,
          refresh_token: typeof tokenData.refresh_token === 'string' ? tokenData.refresh_token.trim() : null,
          expires_at: expiresAt,
          last_refresh: new Date().toISOString(),
          resource_url: resourceURL,
          email,
        });

        const safeAccount = toSafeAccount(account);
        await redisService.set(
          qwenOAuthStateKey(state),
          {
            ...stateInfo,
            callback_completed: true,
            completed_at: Date.now(),
            account_data: safeAccount,
          },
          ttlSeconds
        );
      } catch (error) {
        const message = typeof error?.message === 'string' ? error.message : 'Qwen OAuth失败';
        try {
          await redisService.set(
            qwenOAuthStateKey(state),
            {
              ...stateInfo,
              error: message,
            },
            ttlSeconds
          );
        } catch {
          // ignore
        }
        qwenService.logSafeError(error);
      }
    })();

    res.json({
      success: true,
      data: {
        auth_url: deviceFlow.verification_uri_complete,
        state,
        expires_in: deviceFlow.expires_in,
        interval: deviceFlow.interval,
      },
    });
  } catch (error) {
    logger.error('生成Qwen OAuth登录URL失败:', error.message);
    res.status(500).json({ error: error.message || '生成Qwen OAuth登录URL失败' });
  }
});

/**
 * 轮询 Qwen OAuth 登录状态
 * GET /api/qwen/oauth/status/:state
 * 无需认证（不返回敏感 token），仅用于前端轮询
 */
router.get('/api/qwen/oauth/status/:state', async (req, res) => {
  try {
    if (!redisService.isAvailable()) {
      return res.status(503).json({ error: 'Redis不可用，无法查询Qwen OAuth状态' });
    }

    const { state } = req.params || {};
    const normalized = typeof state === 'string' ? state.trim() : '';
    if (!normalized) {
      return res.status(400).json({ error: '缺少state参数' });
    }

    const stateInfo = await redisService.get(qwenOAuthStateKey(normalized));
    if (!stateInfo) {
      return res.status(404).json({
        error: '无效或已过期的state参数',
        status: 'expired',
      });
    }

    if (stateInfo.callback_completed) {
      return res.json({
        success: true,
        status: 'completed',
        data: stateInfo.account_data || null,
        message: '登录已完成',
      });
    }

    if (stateInfo.error) {
      return res.json({
        success: false,
        status: 'failed',
        error: stateInfo.error,
        message: '登录失败',
      });
    }

    res.json({
      success: true,
      status: 'pending',
      message: '等待用户完成授权...',
    });
  } catch (error) {
    logger.error('查询Qwen OAuth状态失败:', error.message);
    res.status(500).json({ error: error.message || '查询Qwen OAuth状态失败' });
  }
});

/**
 * 导入 QwenCli 导出的 JSON
 * POST /api/qwen/accounts/import
 * Body: { is_shared, credential_json } 或 { is_shared, credential }
 */
router.post('/api/qwen/accounts/import', authenticateApiKey, async (req, res) => {
  try {
    const { is_shared = 0, credential_json, credential, account_name } = req.body || {};

    if (is_shared !== 0 && is_shared !== 1) {
      return res.status(400).json({ error: 'is_shared必须是0或1' });
    }

    let creds = credential;
    if (!creds && typeof credential_json === 'string') {
      try {
        creds = JSON.parse(credential_json);
      } catch {
        return res.status(400).json({ error: 'credential_json不是有效JSON' });
      }
    }

    if (!creds || typeof creds !== 'object') {
      return res.status(400).json({ error: '缺少credential或credential_json' });
    }

    const type = typeof creds.type === 'string' ? creds.type.trim() : '';
    if (type && type !== 'qwen') {
      return res.status(400).json({ error: '只支持type=qwen的凭证文件' });
    }

    const accessToken = typeof creds.access_token === 'string' ? creds.access_token.trim() : '';
    if (!accessToken) {
      return res.status(400).json({ error: '缺少access_token' });
    }

    const refreshToken = typeof creds.refresh_token === 'string' ? creds.refresh_token.trim() : null;
    const email = typeof creds.email === 'string' ? creds.email.trim() : null;
    const resourceURL = qwenService.normalizeResourceURL(creds.resource_url);
    const expiresAt = qwenService.parseExpiredToMillis(creds.expired);
    const lastRefresh = typeof creds.last_refresh === 'string' ? creds.last_refresh.trim() : null;

    const name =
      (typeof account_name === 'string' ? account_name.trim() : '') ||
      email ||
      'Qwen Account';

    const account = await qwenAccountService.createAccount({
      user_id: req.user.user_id,
      account_name: name,
      is_shared,
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_at: expiresAt,
      last_refresh: lastRefresh,
      resource_url: resourceURL,
      email,
    });

    res.json({
      success: true,
      message: 'Qwen账号导入成功',
      data: toSafeAccount(account),
    });
  } catch (error) {
    logger.error('导入Qwen账号失败:', error.message);
    const message = typeof error?.message === 'string' ? error.message : '导入失败';
    res.status(400).json({ error: message });
  }
});

/**
 * 获取当前用户的Qwen账号列表
 * GET /api/qwen/accounts
 */
router.get('/api/qwen/accounts', authenticateApiKey, async (req, res) => {
  try {
    const accounts = await qwenAccountService.getAccountsByUserId(req.user.user_id);
    res.json({ success: true, data: accounts.map(toSafeAccount) });
  } catch (error) {
    logger.error('获取Qwen账号列表失败:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 获取单个Qwen账号
 * GET /api/qwen/accounts/:account_id
 */
router.get('/api/qwen/accounts/:account_id', authenticateApiKey, async (req, res) => {
  try {
    const { account_id } = req.params;
    const account = await qwenAccountService.getAccountById(account_id);
    if (!account) {
      return res.status(404).json({ error: '账号不存在' });
    }
    if (!req.isAdmin && account.user_id !== req.user.user_id) {
      return res.status(403).json({ error: '无权访问该账号' });
    }
    res.json({ success: true, data: toSafeAccount(account) });
  } catch (error) {
    logger.error('获取Qwen账号失败:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 更新Qwen账号状态
 * PUT /api/qwen/accounts/:account_id/status
 * Body: { status }
 */
router.put('/api/qwen/accounts/:account_id/status', authenticateApiKey, async (req, res) => {
  try {
    const { account_id } = req.params;
    const { status } = req.body || {};
    if (status !== 0 && status !== 1) {
      return res.status(400).json({ error: 'status必须是0或1' });
    }

    const account = await qwenAccountService.getAccountById(account_id);
    if (!account) return res.status(404).json({ error: '账号不存在' });
    if (!req.isAdmin && account.user_id !== req.user.user_id) {
      return res.status(403).json({ error: '无权操作该账号' });
    }

    const updated = await qwenAccountService.updateAccountStatus(account_id, status);
    res.json({ success: true, message: '账号状态已更新', data: toSafeAccount(updated) });
  } catch (error) {
    logger.error('更新Qwen账号状态失败:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 修改Qwen账号名称
 * PUT /api/qwen/accounts/:account_id/name
 * Body: { account_name }
 */
router.put('/api/qwen/accounts/:account_id/name', authenticateApiKey, async (req, res) => {
  try {
    const { account_id } = req.params;
    const { account_name } = req.body || {};
    if (!account_name || typeof account_name !== 'string' || !account_name.trim()) {
      return res.status(400).json({ error: 'account_name不能为空' });
    }

    const account = await qwenAccountService.getAccountById(account_id);
    if (!account) return res.status(404).json({ error: '账号不存在' });
    if (!req.isAdmin && account.user_id !== req.user.user_id) {
      return res.status(403).json({ error: '无权操作该账号' });
    }

    const updated = await qwenAccountService.updateAccountName(account_id, account_name);
    res.json({ success: true, message: '账号名称已更新', data: toSafeAccount(updated) });
  } catch (error) {
    logger.error('更新Qwen账号名称失败:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 删除Qwen账号
 * DELETE /api/qwen/accounts/:account_id
 */
router.delete('/api/qwen/accounts/:account_id', authenticateApiKey, async (req, res) => {
  try {
    const { account_id } = req.params;
    const account = await qwenAccountService.getAccountById(account_id);
    if (!account) return res.status(404).json({ error: '账号不存在' });
    if (!req.isAdmin && account.user_id !== req.user.user_id) {
      return res.status(403).json({ error: '无权操作该账号' });
    }
    await qwenAccountService.deleteAccount(account_id);
    res.json({ success: true, message: '账号已删除' });
  } catch (error) {
    logger.error('删除Qwen账号失败:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * 管理员：列出所有Qwen账号（用于排障）
 * GET /api/qwen/admin/accounts
 */
router.get('/api/qwen/admin/accounts', authenticateApiKey, requireAdmin, async (req, res) => {
  try {
    const result = await qwenAccountService.getAvailableAccounts(null, null);
    res.json({ success: true, data: result.map(toSafeAccount) });
  } catch (error) {
    logger.error('管理员查询Qwen账号失败:', error.message);
    res.status(500).json({ error: error.message });
  }
});

export default router;
