<script lang="ts">
  import { onMount, mount } from 'svelte';
  import { GoldenLayout } from 'golden-layout';
  import 'golden-layout/dist/css/goldenlayout-base.css';
  import 'golden-layout/dist/css/themes/goldenlayout-dark-theme.css';
  import AnalysisPane from './AnalysisPane.svelte';
  import ResultsPane from './ResultsPane.svelte';

  let layoutContainer;
  let layout;

  onMount(() => {
    layout = new GoldenLayout(
      {
        root: {
          type: 'row',
          content: [
            { type: 'component', componentType: 'analysis', title: 'Analysis', width: 40 },
            { type: 'component', componentType: 'results', title: 'Results', width: 60 },
          ]
        }
      },
      layoutContainer
    );

    layout.registerComponentFactoryFunction('analysis', (container) => {
      const el = document.createElement('div');
      el.style.height = '100%';
      container.element.appendChild(el);
      mount(AnalysisPane, { target: el });
    });

    layout.registerComponentFactoryFunction('results', (container) => {
      const el = document.createElement('div');
      el.style.height = '100%';
      container.element.appendChild(el);
      mount(ResultsPane, { target: el });
    });

    layout.init();
  });
</script>

<div bind:this={layoutContainer} style="width: 100vw; height: 100vh;"></div>