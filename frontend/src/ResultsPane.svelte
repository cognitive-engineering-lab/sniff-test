<script lang="ts">
    import { Chart, ArcElement, PieController, Legend, Tooltip } from 'chart.js';
    import { selectedRunStore } from './stores.js';
  
    Chart.register(ArcElement, PieController, Legend, Tooltip);
  
    let canvas = $state<HTMLCanvasElement>();
    let chart;
  
    function buildChart(run) {
      if (chart) chart.destroy();
      if (!run || !canvas) return;
      const data = run.data;
  
      chart = new Chart(canvas, {
        type: 'pie',
        data: {
          labels: ['With Obligation', 'No Obligation'],
          datasets: [{
            data: [data.w_obligation, data.w_no_obligation],
            backgroundColor: ['#646cff', '#ce9178'],
            borderColor: '#1e1e1e',
            borderWidth: 2,
          }]
        },
        options: {
          plugins: {
            legend: { labels: { color: '#d4d4d4' } },
            tooltip: {
              callbacks: {
                label: (ctx) => {
                  const pct = (((ctx.raw as number) / data.total_fns_checked) * 100).toFixed(1);
                  return `${ctx.label}: ${ctx.raw} (${pct}%)`;
                }
              }
            }
          }
        }
      });
    }
  
    $effect(() => {
      buildChart($selectedRunStore);
    });
  </script>
  
  {#if $selectedRunStore}
    <div class="pane">
      <h2>{$selectedRunStore.data.total_fns_checked} fns checked for <em>{$selectedRunStore.property}</em> in {$selectedRunStore.data.analysis_time_ms}ms</h2>
      <div class="chart-container">
        <canvas bind:this={canvas}></canvas>
      </div>
    </div>
  {:else}
    <div class="pane empty-pane">
      <div class="empty">Run an analysis to see results</div>
    </div>
  {/if}
  
  <style>
    .pane { padding: 16px; height: 100%; box-sizing: border-box; display: flex; flex-direction: column; align-items: center; justify-content: center; }
    .empty-pane { justify-content: center; }
    h2 { color: #d4d4d4; margin: 0 0 16px; }
    .chart-container { width: 300px; height: 300px; }
    .empty { color: #666; font-size: 14px; }
  </style>