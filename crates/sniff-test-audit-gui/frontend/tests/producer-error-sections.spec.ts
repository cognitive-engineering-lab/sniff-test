import {test,expect} from '@playwright/test';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import Markdown from 'react-markdown';
import {producerErrorSections} from '../src/producer-error-sections';

const render=(markdown:string)=>renderToStaticMarkup(createElement(Markdown,{remarkPlugins:[producerErrorSections],children:markdown}));

for(const heading of ['# Errors','## Error','### eRrOrS','Errors\n------','## **Errors**'])test(`producer documentation selects ${heading}`,()=>{
  const html=render(`Introduction.\n\n${heading}\n\nFailure condition.\n\n# Examples\n\nUnrelated example.`);
  expect(html).toContain('Failure condition.');
  expect(html).not.toContain('Introduction.');
  expect(html).not.toContain('Unrelated example.');
  expect(html).toMatch(/<h[1-6]>/);
});

test('error sections retain nested content and stop at peer or parent headings',()=>{
  const html=render('# Overview\nIntroduction.\n\n## Errors\nFailure condition.\n\n### Details\nNested detail.\n\n### Error\nNested failure.\n\n### Recovery\nNested recovery.\n\n## Examples\nUnrelated peer.\n\n# Error\nOther failure.\n\n## Details\nOther nested detail.\n\n# Notes\nUnrelated parent.');
  for(const text of ['Failure condition.','Nested detail.','Nested failure.','Nested recovery.','Other failure.','Other nested detail.'])expect(html).toContain(text);
  for(const text of ['Introduction.','Unrelated peer.','Unrelated parent.'])expect(html).not.toContain(text);
});

test('code examples do not introduce or terminate error sections',()=>{
  const html=render('```markdown\n# Error\nFake section.\n```\n\n# Errors\nReal failure.\n\n~~~markdown\n# Examples\nIncluded example.\n~~~\n\n# Examples\nUnrelated example.');
  expect(html).toContain('Real failure.');
  expect(html).toContain('Included example.');
  expect(html).not.toContain('Fake section.');
  expect(html).not.toContain('Unrelated example.');
});

test('selected sections retain reference links defined elsewhere',()=>{
  const html=render('[condition]: https://example.com/condition "Condition"\n\nIntroduction.\n\n# Errors\nSee [failure details][condition].\n\n# Examples\nOther text.\n\n[unused]: https://example.com/unused');
  expect(html).toContain('<a href="https://example.com/condition" title="Condition">failure details</a>');
  expect(html).not.toContain('Introduction.');
  expect(html).not.toContain('Other text.');
});

test('without a matching section the full documentation remains',()=>{
  const docs='Overview.\n\n# Error handling\nGeneral advice.\n\n```markdown\n# Errors\nExample heading.\n```\n\n> # Error\n> Quoted heading.\n\n# Returns\nReturns None when absent.';
  expect(render(docs)).toBe(renderToStaticMarkup(createElement(Markdown,{children:docs})));
});

test('an explicitly empty error section does not fall back to other documentation',()=>{
  expect(render('Introduction.\n\n# Errors\n\n# Examples\nUnrelated example.')).toBe('<h1>Errors</h1>');
});

test('producer titles appear only with full-document fallback',()=>{
  const renderTitled=(markdown:string,title:string)=>renderToStaticMarkup(createElement(Markdown,{remarkPlugins:[[producerErrorSections,{fallbackTitle:title}]],children:markdown}));
  for(const title of ['Result Producer','Option Producer']){
    for(const heading of ['Errors','Error']){
      const html=renderTitled(`# ${heading}\nFailure condition.`,title);
      expect(html).toContain(`<h1>${heading}</h1>`);
      expect(html).not.toContain(title);
    }
    const html=renderTitled('Full documentation.',title);
    expect(html).toContain(`<h1 class="producer-title">${title}</h1>`);
    expect(html).toContain('Full documentation.');
  }
});
