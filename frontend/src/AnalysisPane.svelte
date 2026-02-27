<script lang="ts">
    import { onMount } from 'svelte';
    import { runsStore, selectedRunStore } from './stores.js';
  
    let selected = $state('panic-freedom');
    let loading = $state(false);
    let crateName = $state('');
  
    const properties = ['panic-freedom', 'ub-freedom'];
  
    onMount(async () => {
      const res = await fetch('/api/crate-name');
      crateName = await res.text();
    });
  
    async function analyze() {
      loading = true;
      try {
        const res = await fetch(`/api/analyze?property=${selected}`);
        const data = await res.json();
        const run = { id: Date.now(), property: selected, data };
        runsStore.update(runs => [run, ...runs]);
        selectedRunStore.set(run);
      } catch (e) {
        console.error('fetch error:', e);
      } finally {
        loading = false;
      }
    }
  </script>
  
  <div class="pane">
    <h2>Analyze {crateName}</h2>
  
    <div class="controls">
      <select bind:value={selected}>
        {#each properties as property}
          <option value={property}>{property}</option>
        {/each}
      </select>
      <button onclick={analyze} disabled={loading}>
        {loading ? 'Analyzing...' : 'Run Analysis'}
      </button>
    </div>
  
    {#if loading}
      <div class="thinking-bar"><div class="thinking-bar-inner"></div></div>
    {/if}
  
    {#if $runsStore.length > 0}
      <div class="run-history">
        <h3>Previous Runs</h3>
        {#each $runsStore as run}
          <button
            class="run-item"
            class:selected={$selectedRunStore?.id === run.id}
            onclick={() => selectedRunStore.set(run)}
          >
            <span class="run-property">{run.property}</span>
            <span class="run-stats">{run.data.total_fns_checked} fns checked · {run.data.analysis_time_ms}ms</span>
          </button>
        {/each}
      </div>
    {/if}
  </div>
  
  <style>
    .pane { padding: 16px; height: 100%; box-sizing: border-box; display: flex; flex-direction: column; }
    h2 { margin: 0 0 16px; color: #d4d4d4; }
    h3 { margin: 0 0 8px; color: #999; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
    .controls { display: flex; gap: 8px; }
    select, button { padding: 6px 12px; background: #2d2d2d; color: #d4d4d4; border: 1px solid #555; border-radius: 4px; cursor: pointer; }
    button:disabled { opacity: 0.5; }
    .thinking-bar { margin-top: 16px; width: 100%; height: 6px; background: #333; border-radius: 3px; overflow: hidden; }
    .thinking-bar-inner { height: 100%; width: 40%; background: #646cff; border-radius: 3px; animation: slide 1.2s ease-in-out infinite; }
    @keyframes slide { 0% { transform: translateX(-100%); } 100% { transform: translateX(350%); } }
    .run-history { margin-top: 24px; display: flex; flex-direction: column; gap: 4px; }
    .run-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #2d2d2d; border: 1px solid #444; border-radius: 4px; text-align: left; }
    .run-item.selected { border-color: #646cff; background: #2a2a3e; }
    .run-item:hover { border-color: #666; }
    .run-property { color: #d4d4d4; font-size: 13px; }
    .run-stats { color: #888; font-size: 12px; }
  </style>