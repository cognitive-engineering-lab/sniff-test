import {test,expect} from '@playwright/test';
import {displaySourcePath} from '../src/source-path';

test('source paths retain crate identity and workspace directory boundaries',()=>{
  const cases=[
    ['/work/app/src/lib.rs','/work/app','src/lib.rs'],
    ['/work/app/src/lib.rs','/work/app/','src/lib.rs'],
    ['/work/apple/src/lib.rs','/work/app','/work/apple/src/lib.rs'],
    ['/home/me/.cargo/registry/src/index.crates.io-123/wyz-0.5.1/src/comu.rs','/work/app','wyz-0.5.1/src/comu.rs'],
    ['/cache/registry/src/private-456/wyz-0.5.1/src/deep/lib.rs','/work/app','wyz-0.5.1/src/deep/lib.rs'],
    ['C:\\cargo\\registry\\src\\index-123\\wyz-0.5.1\\src\\lib.rs','C:\\work\\app','wyz-0.5.1/src/lib.rs'],
    ['C:\\work\\app\\src\\lib.rs','C:\\work\\app\\','src/lib.rs'],
    ['/src/lib.rs','/','src/lib.rs'],
    ['src/lib.rs','/work/app','src/lib.rs'],
    ['wyz-0.5.1/src/lib.rs','','wyz-0.5.1/src/lib.rs'],
    ['/external/path-dep/src/lib.rs','/work/app','/external/path-dep/src/lib.rs'],
    ['/cargo/git/checkouts/dep/hash/src/lib.rs','/work/app','/cargo/git/checkouts/dep/hash/src/lib.rs'],
    ['/toolchain/library/core/src/lib.rs','/work/app','/toolchain/library/core/src/lib.rs'],
    ['/home/me/.rustup/toolchains/nightly-2026-05-01-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/option.rs','/work/app','nightly-2026-05-01-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/option.rs'],
    ['/custom/rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/lib.rs','/work/app','stable-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/lib.rs'],
    ['C:\\rustup\\toolchains\\nightly-aarch64-pc-windows-msvc\\lib\\rustlib\\src\\rust\\library\\alloc\\src\\lib.rs','C:\\work\\app','nightly-aarch64-pc-windows-msvc/lib/rustlib/src/rust/library/alloc/src/lib.rs'],
    ['/work/app/toolchains/custom/lib/src/lib.rs','/work/app','toolchains/custom/lib/src/lib.rs'],
    ['/custom/my-toolchains/nightly/lib.rs','/work/app','/custom/my-toolchains/nightly/lib.rs'],
    ['/custom/toolchains/nightly','/work/app','/custom/toolchains/nightly'],
    ['/cache/registry/src/wyz-0.5.1','/work/app','/cache/registry/src/wyz-0.5.1'],
    ['/work/app/src/lib.rs','','/work/app/src/lib.rs'],
  ];
  for(const [path,root,expected] of cases)expect(displaySourcePath(path,root),path).toBe(expected);
});
