// Display only: callers must retain the original path for source operations.
export function displaySourcePath(path:string, root:string):string {
  const normalized=path.replace(/\\/g,'/');
  const workspace=root.replace(/\\/g,'/').replace(/\/+$/,'');
  if(root && normalized.startsWith(workspace+'/'))return normalized.slice(workspace.length+1);
  const registry=normalized.match(/(?:^|\/)registry\/src\/[^/]+\/([^/]+\/.+)$/);
  if(registry)return registry[1];
  const toolchain=normalized.match(/(?:^|\/)toolchains\/([^/]+\/.+)$/);
  return toolchain ? toolchain[1] : path;
}
