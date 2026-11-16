import {test,expect} from '@playwright/test';
import {producerDocumentation,producerPosition,sourcePosition,unwrapKind} from '../src/unwrap-producer';

test('unwrap producer lookup selects the precise call and skips indirect values',()=>{
  for(const expression of ['fetch().unwrap()','store.fetch().unwrap()','Type::fetch::<T>().unwrap()','(fetch()).unwrap()']){
    const source=`fn f(){ ${expression}; other().unwrap(); }`;
    const from=source.indexOf(expression),to=from+expression.length;
    expect(producerPosition(source,from,to)).toBe(source.indexOf('fetch'));
    const other=source.indexOf('other');
    expect(producerPosition(source,other,source.indexOf(';',other))).toBe(other);
  }
  for(const expression of ['value.unwrap()','values[0].unwrap()','fetch().expect("valid")','fake.unwrap(1)']){
    const source=`fn f(){${expression};}`;
    expect(producerPosition(source,source.indexOf(expression),source.indexOf(';'))).toBeUndefined();
  }
  const source='fn f(){ a().unwrap(); b().unwrap(); }';
  expect(producerPosition(source,0,source.length)).toBeUndefined();
});

test('only canonical standard unwraps enable the section',()=>{
  expect(unwrapKind(['core::option::Option<T>::unwrap'])).toBe('Option');
  expect(unwrapKind(['core::result::Result::<T, E>::unwrap'])).toBe('Result');
  for(const name of ['custom::Option::unwrap','core::result::Result::unwrap_err','core::option::Option::expect'])expect(unwrapKind([name])).toBeUndefined();
});

test('hover declarations move after full documentation without consuming examples',()=>{
  const prototype='pub fn fetch<T>(key: T) -> Result<Value, Error>';
  const docs='Loads a value.\n\n# Errors\nReturns Err when absent.\n\n```rust\nfn example() {}\n```';
  const hover={contents:{kind:'markdown' as const,value:'```rust\napp::store\n```\n\n```rust\n'+prototype+'\n```\n\n---\n\n'+docs}};
  expect(producerDocumentation(hover)).toEqual({markdown:docs,prototype});
  expect(producerDocumentation({contents:[{language:'rust',value:prototype}]})).toEqual({markdown:'',prototype});
  expect(producerDocumentation({contents:{kind:'plaintext',value:'fn fetch() -> Option<Value>'}})).toEqual({markdown:'',prototype:'fn fetch() -> Option<Value>'});
  expect(producerDocumentation(null)).toBeUndefined();
  expect(producerDocumentation({contents:[]})).toBeUndefined();
  expect(producerDocumentation({contents:docs})).toEqual({markdown:docs});
});

test('producer positions account for UTF-8, CRLF, and Unicode',()=>{
  const source='// λ 🦀\r\nfn f(){ fetch().unwrap(); }';
  const from=new TextEncoder().encode(source.slice(0,source.indexOf('fetch'))).length;
  const end=new TextEncoder().encode(source.slice(0,source.indexOf(';'))).length;
  const normalized=source.replace(/\r\n/g,'\n');
  expect(producerPosition(normalized,sourcePosition(source,from),sourcePosition(source,end))).toBe(normalized.indexOf('fetch'));
});
