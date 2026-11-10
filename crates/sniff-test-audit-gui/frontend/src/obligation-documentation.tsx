import React from 'react';
import Markdown, {type Components} from 'react-markdown';
import {RustPrototype} from './rust-prototype';

export type ObligationDocumentation = {function:string; markdown:string; prototype?:string|null};

const components:Components = {
  h1:({children})=><h4>{children}</h4>,
  h2:({children})=><h5>{children}</h5>,
  h3:({children})=><h6>{children}</h6>,
  h4:({children})=><h6>{children}</h6>,
  h5:({children})=><h6>{children}</h6>,
  h6:({children})=><h6>{children}</h6>,
  a:({href,title,children})=>href&&/^https?:\/\//i.test(href)
    ?<a href={href} title={title} target="_blank" rel="noopener noreferrer">{children}</a>
    :<>{children}</>,
  img:({alt})=><>{alt}</>,
};

export function ObligationDocumentationPanel({documentation}:{documentation:ObligationDocumentation}) {
  return <section className="obligation-context" aria-label="Obligation">
    <div className="obligation-markdown" role="region" aria-label="Obligation documentation" tabIndex={0}>
      <Markdown components={components} skipHtml>{documentation.markdown}</Markdown>
    </div>
    {documentation.prototype&&<pre className="obligation-prototype" aria-label="Function prototype" tabIndex={0}><RustPrototype text={documentation.prototype}/></pre>}
  </section>;
}
