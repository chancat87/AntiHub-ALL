import logger from '../utils/logger.js';
import quotaService from './quota.service.js';

/**
 * 说明：
 * 这个文件用于“补丁式”兼容 Antigravity fetchAvailableModels 的不同返回字段，
 * 避免因为字段命名差异（snake_case/camelCase）导致配额永远显示为 100%。
 *
 * 设计取舍：
 * - 不直接改动原始 `quota.service.js`（当前为 CRLF，工具补丁容易匹配失败）。
 * - 通过对默认导出的 `quotaService` 实例做一次性 monkey patch，确保全局生效。
 */

function normalizeNumberValue(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function normalizeQuotaFraction(value) {
  const normalized = normalizeNumberValue(value);
  if (normalized !== null) {
    if (!Number.isFinite(normalized)) return null;
    // Antigravity 有时会把 remainingFraction 作为百分比数值返回（例如 80 表示 80%）。
    // 统一规范为 0~1 的小数，避免写入 DB（numeric(5,4)）时报错或 UI 误判为永远 100%。
    let fraction = normalized;
    if (fraction > 1 && fraction <= 100) fraction /= 100;
    if (fraction < 0) fraction = 0;
    // 避免异常值把 numeric(5,4) 顶爆；正常 remainingFraction 应该不会超过 1。
    if (fraction > 9.9999) fraction = 9.9999;
    return fraction;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    if (trimmed.endsWith('%')) {
      const parsed = Number(trimmed.slice(0, -1));
      return Number.isFinite(parsed) ? parsed / 100 : null;
    }
  }

  return null;
}

function extractModelQuotaInfo(modelInfo) {
  if (!modelInfo || typeof modelInfo !== 'object') {
    return { remainingFraction: null, resetTime: undefined };
  }

  const quotaInfo = modelInfo.quotaInfo ?? modelInfo.quota_info ?? null;
  if (!quotaInfo || typeof quotaInfo !== 'object') {
    return { remainingFraction: null, resetTime: undefined };
  }

  const remainingValue =
    quotaInfo.remainingFraction ?? quotaInfo.remaining_fraction ?? quotaInfo.remaining;
  const remainingFraction = normalizeQuotaFraction(remainingValue);

  const resetValue = quotaInfo.resetTime ?? quotaInfo.reset_time;
  const resetTime = typeof resetValue === 'string' ? resetValue : undefined;

  return { remainingFraction, resetTime };
}

// 暴露给其他模块复用（例如 oauth.service 在构建共享配额池时）。
quotaService.normalizeNumberValue = normalizeNumberValue;
quotaService.normalizeQuotaFraction = normalizeQuotaFraction;
quotaService.extractModelQuotaInfo = extractModelQuotaInfo;

// 只 patch 一次，避免热重载/重复 import 时反复包裹。
if (!quotaService.__quotaCompatPatched) {
  quotaService.__quotaCompatPatched = true;

  const original = quotaService.updateQuotasFromModels?.bind(quotaService);

  quotaService.updateQuotasFromModels = async (cookie_id, modelsData) => {
    const results = [];

    try {
      const entries = modelsData && typeof modelsData === 'object' ? Object.entries(modelsData) : [];

      for (const [modelName, modelInfo] of entries) {
        const { remainingFraction, resetTime } = extractModelQuotaInfo(modelInfo);

        // 没有任何可用的 quota 字段：跳过（避免默认写入 1.0 造成“永远 100%”假象）
        if (remainingFraction === null && !resetTime) continue;

        // remainingFraction 缺失但有 resetTime：按 0 处理（参考 CPA 前端逻辑）
        const quotaValue = remainingFraction !== null ? remainingFraction : 0;

        const quota = await quotaService.upsertQuota(cookie_id, modelName, {
          remainingFraction: quotaValue,
          resetTime,
        });
        results.push(quota);
      }

      logger.info(`批量更新配额成功: cookie_id=${cookie_id}, 更新了 ${results.length} 个模型`);
      return results;
    } catch (error) {
      // 如果原始实现存在且本次兼容逻辑失败，回退一次（不影响主流程）。
      if (typeof original === 'function') {
        try {
          return await original(cookie_id, modelsData);
        } catch {
          // ignore
        }
      }
      logger.error('批量更新配额失败:', error.message);
      throw error;
    }
  };
}

export default quotaService;
