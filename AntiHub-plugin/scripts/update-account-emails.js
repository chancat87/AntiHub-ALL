import database from '../src/db/database.js';
import logger from '../src/utils/logger.js';
import oauthService from '../src/services/oauth.service.js';
import accountService from '../src/services/account.service.js';
import quotaService from '../src/services/quota.service.compat.js';
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
 * 从Google API获取用户邮箱
 * @param {string} accessToken - 访问令牌
 * @returns {Promise<string|null>} 邮箱地址
 */
async function fetchUserEmail(accessToken) {
  try {
    const userInfo = await oauthService.getUserInfo(accessToken);
    return userInfo.email || null;
  } catch (error) {
    throw error;
  }
}

/**
 * 更新账号的邮箱字段
 * @param {string} cookieId - Cookie ID
 * @param {string} email - 邮箱地址
 */
async function updateAccountEmail(cookieId, email) {
  await database.query(
    'UPDATE accounts SET email = $1, updated_at = CURRENT_TIMESTAMP WHERE cookie_id = $2',
    [email, cookieId]
  );
}

/**
 * 删除重复账号并更新共享配额
 * @param {Object} account - 要删除的账号
 */
async function removeDuplicateAccount(account) {
  const { cookie_id, user_id, is_shared } = account;
  
  logger.info(`  正在删除重复账号: ${cookie_id}`);
  
  // 如果是共享账号，需要移除用户共享配额池中的配额
  if (is_shared === 1) {
    logger.info(`  正在移除用户共享配额...`);
    
    // 获取该账号的配额信息
    const accountQuotas = await quotaService.getQuotasByCookieId(cookie_id);
    
    // 移除每个模型的配额
    for (const quota of accountQuotas) {
      try {
        await quotaService.removeUserSharedQuota(
          user_id,
          quota.model_name,
          quota.quota
        );
        logger.info(`    已移除共享配额: model=${quota.model_name}, quota=${quota.quota}`);
      } catch (quotaError) {
        logger.error(`    移除共享配额失败: model=${quota.model_name}, error=${quotaError.message}`);
      }
    }
  }
  
  // 删除账号
  await accountService.deleteAccount(cookie_id);
  logger.info(`  ✓ 账号已删除: ${cookie_id}`);
}

/**
 * 为所有账号添加邮箱信息
 */
async function updateAllAccountEmails() {
  try {
    // 初始化数据库连接
    database.initialize(dbConfig);
    logger.info('数据库连接已初始化');
    
    logger.info('开始为所有账号添加邮箱信息...\n');
    
    // 获取所有没有邮箱的账号
    const result = await database.query(
      `SELECT cookie_id, user_id, name, access_token, refresh_token, expires_at, status 
       FROM accounts 
       WHERE email IS NULL 
       ORDER BY created_at ASC`
    );
    
    const accounts = result.rows;
    logger.info(`找到 ${accounts.length} 个需要添加邮箱的账号\n`);
    
    if (accounts.length === 0) {
      logger.info('所有账号都已有邮箱信息，无需更新');
      return;
    }
    
    let successCount = 0;
    let failedCount = 0;
    let skippedCount = 0;
    let tokenRefreshCount = 0;
    const results = [];
    const emailMap = new Map(); // 用于检测重复邮箱
    
    for (let i = 0; i < accounts.length; i++) {
      const account = accounts[i];
      logger.info(`[${i + 1}/${accounts.length}] 处理账号: ${account.cookie_id}`);
      logger.info(`  当前名称: ${account.name || '(未设置)'}`);
      logger.info(`  状态: ${account.status === 1 ? '启用' : '禁用'}`);
      
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
              logger.error(`  账号需要重新授权`);
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
        
        // 从API获取邮箱信息
        logger.info(`  正在从Google API获取邮箱信息...`);
        const email = await fetchUserEmail(accessToken);
        
        if (!email) {
          logger.warn(`  ✗ 无法获取邮箱信息`);
          failedCount++;
          results.push({
            cookie_id: account.cookie_id,
            success: false,
            error: '无法获取邮箱'
          });
          continue;
        }
        
        logger.info(`  获取到邮箱: ${email}`);
        
        // 检查邮箱是否重复（在本次处理中）
        if (emailMap.has(email)) {
          const existingCookieId = emailMap.get(email);
          logger.warn(`  ⚠ 邮箱重复! 已存在于账号: ${existingCookieId}`);
          logger.warn(`  正在删除此重复账号...`);
          
          try {
            await removeDuplicateAccount(account);
            skippedCount++;
            results.push({
              cookie_id: account.cookie_id,
              success: false,
              removed: true,
              error: `邮箱重复已删除: ${email} (保留 ${existingCookieId})`
            });
          } catch (removeError) {
            logger.error(`  ✗ 删除重复账号失败: ${removeError.message}`);
            results.push({
              cookie_id: account.cookie_id,
              success: false,
              error: `删除重复账号失败: ${removeError.message}`
            });
            failedCount++;
          }
          continue;
        }
        
        // 检查数据库中是否已存在此邮箱
        const existingResult = await database.query(
          'SELECT cookie_id FROM accounts WHERE email = $1',
          [email]
        );
        
        if (existingResult.rows.length > 0) {
          const existingCookieId = existingResult.rows[0].cookie_id;
          logger.warn(`  ⚠ 邮箱已存在于数据库中: ${existingCookieId}`);
          logger.warn(`  正在删除此重复账号...`);
          
          try {
            await removeDuplicateAccount(account);
            skippedCount++;
            results.push({
              cookie_id: account.cookie_id,
              success: false,
              removed: true,
              error: `邮箱重复已删除: ${email} (保留 ${existingCookieId})`
            });
          } catch (removeError) {
            logger.error(`  ✗ 删除重复账号失败: ${removeError.message}`);
            results.push({
              cookie_id: account.cookie_id,
              success: false,
              error: `删除重复账号失败: ${removeError.message}`
            });
            failedCount++;
          }
          continue;
        }
        
        // 更新邮箱
        await updateAccountEmail(account.cookie_id, email);
        emailMap.set(email, account.cookie_id);
        
        logger.info(`  ✓ 邮箱已更新: ${email}`);
        successCount++;
        results.push({
          cookie_id: account.cookie_id,
          success: true,
          email: email
        });
        
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
    
    logger.info('========== 更新完成 ==========');
    logger.info(`总账号数: ${accounts.length}`);
    logger.info(`成功: ${successCount}`);
    logger.info(`失败: ${failedCount}`);
    logger.info(`删除(重复): ${skippedCount}`);
    logger.info(`Token刷新: ${tokenRefreshCount}`);
    logger.info('==============================\n');
    
    // 显示删除的重复账号
    const removedAccounts = results.filter(r => r.removed);
    if (removedAccounts.length > 0) {
      logger.info('已删除的重复账号:');
      for (const result of removedAccounts) {
        logger.info(`  - ${result.cookie_id}: ${result.error}`);
      }
      logger.info('');
    }
    
    // 显示失败的账号
    const failedAccounts = results.filter(r => !r.success && !r.removed);
    if (failedAccounts.length > 0) {
      logger.info('处理失败的账号:');
      for (const result of failedAccounts) {
        logger.info(`  - ${result.cookie_id}: ${result.error}`);
      }
      logger.info('');
    }
    
    // 显示成功的账号
    if (successCount > 0) {
      logger.info('成功更新的账号:');
      for (const result of results) {
        if (result.success) {
          logger.info(`  - ${result.cookie_id}: ${result.email}`);
        }
      }
      logger.info('');
    }
    
  } catch (error) {
    logger.error('更新邮箱失败:', error.message);
    throw error;
  } finally {
    // 关闭数据库连接
    await database.close();
  }
}

// 运行脚本
updateAllAccountEmails()
  .then(() => {
    logger.info('\n脚本执行成功');
    process.exit(0);
  })
  .catch((error) => {
    logger.error('\n脚本执行失败:', error);
    process.exit(1);
  });
