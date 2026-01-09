'use client';

import { useEffect, useState } from "react"
import { IconUsers, IconCpu, IconChartBar, IconActivity } from "@tabler/icons-react"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardAction,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import {
  getSharedPoolStats,
  getQuotaConsumption,
  getSharedPoolQuotas,
  getKiroAccounts,
  getKiroConsumptionStats,
  type SharedPoolStats,
  type UserConsumption,
  type KiroConsumptionStats
} from "@/lib/api"

interface ComputedStats {
  totalAccounts: number; // Antigravity + Kiro 总账号数
  activeAccounts: number; // Antigravity 活跃账号数
  totalKiroAccounts: number; // Kiro 总账号数
  activeKiroAccounts: number; // Kiro 活跃账号数
  totalModels: number;
  availableModels: number;
  consumedLast24h: number; // Antigravity 24小时消耗
  kiroConsumedLast24h: number; // Kiro 24小时消耗
  callsLast24h: number; // Antigravity 24小时调用
  kiroCallsLast24h: number; // Kiro 24小时调用
  totalRequests: number; // Antigravity 总调用
  totalQuotaConsumed: number; // Antigravity 总消耗
  totalKiroRequests: number; // Kiro 总调用
  totalKiroQuotaConsumed: number; // Kiro 总消耗
}

export function SectionCards() {
  const [stats, setStats] = useState<ComputedStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadStats = async () => {
      try {
        // 使用新的统计端点
        const [poolStats, consumptionData, sharedPoolData] = await Promise.all([
          getSharedPoolStats(),
          getQuotaConsumption({ limit: 1000 }),
          getSharedPoolQuotas()
        ]);

        // 计算模型统计
        const models = Object.entries(poolStats.quotas_by_model);
        const totalModels = models.length;
        const availableModels = models.filter(([_, m]) => m.total_quota > 0 && m.status === 1).length;

        // 计算24小时内的消耗
        const now = new Date();
        const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const recentConsumption = consumptionData.filter(c => new Date(c.consumed_at) >= last24h);
        
        const consumedLast24h = recentConsumption.reduce((sum, c) => sum + parseFloat(c.quota_consumed), 0);
        const callsLast24h = recentConsumption.length;

        // 获取用户总消费统计
        const userConsumption = sharedPoolData.user_consumption;

        // 获取 Kiro 数据
        let kiroAccounts: any[] = [];
        let kiroStats: KiroConsumptionStats | null = null;
        let kiroConsumedLast24h = 0;
        let kiroCallsLast24h = 0;

        try {
          // 获取 Kiro 账号
          kiroAccounts = await getKiroAccounts();

          // 获取 Kiro 消费统计
          kiroStats = await getKiroConsumptionStats();
        } catch (err) {
          console.warn('加载 Kiro 数据失败，仅显示 Antigravity 数据', err);
        }

        // 计算 Kiro 24小时数据
        if (kiroStats) {
          kiroConsumedLast24h = parseFloat(kiroStats.total_credit);
          kiroCallsLast24h = parseInt(kiroStats.total_requests);
        }

        setStats({
          totalAccounts: poolStats.accounts.total_shared + kiroAccounts.length,
          activeAccounts: poolStats.accounts.active_shared,
          totalKiroAccounts: kiroAccounts.length,
          activeKiroAccounts: kiroAccounts.filter(a => a.status === 1).length,
          totalModels,
          availableModels,
          consumedLast24h,
          kiroConsumedLast24h,
          callsLast24h,
          kiroCallsLast24h,
          totalRequests: userConsumption?.total_requests || 0,
          totalQuotaConsumed: userConsumption?.total_quota_consumed || 0,
          totalKiroRequests: kiroStats ? parseInt(kiroStats.total_requests) : 0,
          totalKiroQuotaConsumed: kiroStats ? parseFloat(kiroStats.total_credit) : 0
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : '加载数据失败');
      } finally {
        setIsLoading(false);
      }
    };

    loadStats();
  }, []);

  if (isLoading) {
    return (
      <div className="*:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card dark:*:data-[slot=card]:bg-card grid grid-cols-1 gap-4 px-4 *:data-[slot=card]:bg-gradient-to-t *:data-[slot=card]:shadow-xs lg:px-6 @xl/main:grid-cols-2 @5xl/main:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i} className="@container/card">
            <CardHeader>
              <Skeleton className="h-4 w-32 mb-2" />
              <Skeleton className="h-8 w-24" />
            </CardHeader>
            <CardFooter className="flex-col items-start gap-1.5">
              <Skeleton className="h-3 w-40" />
              <Skeleton className="h-3 w-32" />
            </CardFooter>
          </Card>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-4 lg:px-6">
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-500">
          {error}
        </div>
      </div>
    );
  }

  const accountAvailabilityRate = stats && stats.totalAccounts > 0
    ? ((stats.activeAccounts / stats.totalAccounts) * 100).toFixed(1)
    : '0';
  const modelAvailabilityRate = stats && stats.totalModels > 0
    ? ((stats.availableModels / stats.totalModels) * 100).toFixed(1)
    : '0';

  return (
    <div className="*:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card dark:*:data-[slot=card]:bg-card grid grid-cols-1 gap-4 px-4 *:data-[slot=card]:bg-gradient-to-t *:data-[slot=card]:shadow-xs lg:px-6 @xl/main:grid-cols-2 @5xl/main:grid-cols-4">
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>账户总数</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {stats?.totalAccounts || 0}
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              <IconUsers className="size-4" />
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="text-muted-foreground">
            全部渠道合计
          </div>
        </CardFooter>
      </Card>
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>活跃账号数</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {(stats?.activeAccounts || 0) + (stats?.activeKiroAccounts || 0)}
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              <IconCpu className="size-4" />
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="text-muted-foreground">
            全部渠道活跃账号
          </div>
        </CardFooter>
      </Card>
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>24小时配额消耗</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {((stats?.consumedLast24h || 0) + (stats?.kiroConsumedLast24h || 0)).toFixed(2)}
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              <IconChartBar className="size-4" />
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium">
            总消耗: {((stats?.totalQuotaConsumed || 0) + (stats?.totalKiroQuotaConsumed || 0)).toFixed(2)}
          </div>
          <div className="text-muted-foreground">全部渠道配额消耗合计</div>
        </CardFooter>
      </Card>
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>24小时调用量</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {((stats?.callsLast24h || 0) + (stats?.kiroCallsLast24h || 0)).toLocaleString()}
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              <IconActivity className="size-4" />
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium">
            总调用: {((stats?.totalRequests || 0) + (stats?.totalKiroRequests || 0)).toLocaleString()} 次
          </div>
          <div className="text-muted-foreground">全部渠道 API 调用合计</div>
        </CardFooter>
      </Card>
    </div>
  )
}
