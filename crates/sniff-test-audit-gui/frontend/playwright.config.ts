import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'tests', timeout:60000, workers:1, use:{viewport:{width:1440,height:960}, screenshot:'only-on-failure'}, reporter:'list'});
