!function(){"use strict";var n,t,e,r,o,u,i,c,f,a={},p={};function l(n){var t=p[n];if(void 0!==t)return t.exports;var e=p[n]={exports:{}},r=!0;try{a[n](e,e.exports,l),r=!1}finally{r&&delete p[n]}return e.exports}l.m=a,n="function"==typeof Symbol?Symbol("webpack queues"):"__webpack_queues__",t="function"==typeof Symbol?Symbol("webpack exports"):"__webpack_exports__",e="function"==typeof Symbol?Symbol("webpack error"):"__webpack_error__",r=function(n){n&&!n.d&&(n.d=1,n.forEach(function(n){n.r--}),n.forEach(function(n){n.r--?n.r++:n()}))},l.a=function(o,u,i){i&&((c=[]).d=1);var c,f,a,p,l=new Set,s=o.exports,b=new Promise(function(n,t){p=t,a=n});b[t]=s,b[n]=function(n){c&&n(c),l.forEach(n),b.catch(function(){})},o.exports=b,u(function(o){f=o.map(function(o){if(null!==o&&"object"==typeof o){if(o[n])return o;if(o.then){var u=[];u.d=0,o.then(function(n){i[t]=n,r(u)},function(n){i[e]=n,r(u)});var i={};return i[n]=function(n){n(u)},i}}var c={};return c[n]=function(){},c[t]=o,c});var u,i=function(){return f.map(function(n){if(n[e])throw n[e];return n[t]})},a=new Promise(function(t){(u=function(){t(i)}).r=0;var e=function(n){n===c||l.has(n)||(l.add(n),n&&!n.d&&(u.r++,n.push(u)))};f.map(function(t){t[n](e)})});return u.r?a:i()},function(n){n?p(b[e]=n):a(s),r(c)}),c&&(c.d=0)},o=[],l.O=function(n,t,e,r){if(t){r=r||0;for(var u=o.length;u>0&&o[u-1][2]>r;u--)o[u]=o[u-1];o[u]=[t,e,r];return}for(var i=1/0,u=0;u<o.length;u++){for(var t=o[u][0],e=o[u][1],r=o[u][2],c=!0,f=0;f<t.length;f++)i>=r&&Object.keys(l.O).every(function(n){return l.O[n](t[f])})?t.splice(f--,1):(c=!1,r<i&&(i=r));if(c){o.splice(u--,1);var a=e();void 0!==a&&(n=a)}}return n},l.n=function(n){var t=n&&n.__esModule?function(){return n.default}:function(){return n};return l.d(t,{a:t}),t},l.d=function(n,t){for(var e in t)l.o(t,e)&&!l.o(n,e)&&Object.defineProperty(n,e,{enumerable:!0,get:t[e]})},l.u=function(n){return"static/chunks/"+n+".3bfcdf9703395a54.js"},l.g=function(){if("object"==typeof globalThis)return globalThis;try{return this||Function("return this")()}catch(n){if("object"==typeof window)return window}}(),l.o=function(n,t){return Object.prototype.hasOwnProperty.call(n,t)},l.r=function(n){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(n,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(n,"__esModule",{value:!0})},l.tt=function(){return void 0===u&&(u={createScriptURL:function(n){return n}},"undefined"!=typeof trustedTypes&&trustedTypes.createPolicy&&(u=trustedTypes.createPolicy("nextjs#bundler",u))),u},l.tu=function(n){return l.tt().createScriptURL(n)},l.p="/04-zkapp-browser-ui/_next/",l.b=document.baseURI||self.location.href,i={272:0},l.O.j=function(n){return 0===i[n]},c=function(n,t){var e,r,o=t[0],u=t[1],c=t[2],f=0;if(o.some(function(n){return 0!==i[n]})){for(e in u)l.o(u,e)&&(l.m[e]=u[e]);if(c)var a=c(l)}for(n&&n(t);f<o.length;f++)r=o[f],l.o(i,r)&&i[r]&&i[r][0](),i[r]=0;return l.O(a)},(f=self.webpackChunk_N_E=self.webpackChunk_N_E||[]).forEach(c.bind(null,0)),f.push=c.bind(null,f.push.bind(f))}();