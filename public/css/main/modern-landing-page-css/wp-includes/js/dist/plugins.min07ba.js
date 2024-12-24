/*! This file is auto-generated */
(()=>{"use strict";var e={n:n=>{var r=n&&n.__esModule?()=>n.default:()=>n;return e.d(r,{a:r}),r},d:(n,r)=>{for(var t in r)e.o(r,t)&&!e.o(n,t)&&Object.defineProperty(n,t,{enumerable:!0,get:r[t]})},o:(e,n)=>Object.prototype.hasOwnProperty.call(e,n),r:e=>{"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})}},n={};e.r(n),e.d(n,{PluginArea:()=>P,getPlugin:()=>h,getPlugins:()=>y,registerPlugin:()=>f,unregisterPlugin:()=>w,usePluginContext:()=>c,withPluginContext:()=>p});const r=window.React;const t=window.wp.element,o=window.wp.hooks,i=window.wp.isShallowEqual;var l=e.n(i);const s=window.wp.compose,u=(0,t.createContext)({name:null,icon:null}),a=u.Provider;function c(){return(0,t.useContext)(u)}const p=e=>(0,s.createHigherOrderComponent)((n=>t=>(0,r.createElement)(u.Consumer,null,(o=>(0,r.createElement)(n,{...t,...e(o,t)})))),"withPluginContext");class g extends t.Component{constructor(e){super(e),this.state={hasError:!1}}static getDerivedStateFromError(){return{hasError:!0}}componentDidCatch(e){const{name:n,onError:r}=this.props;r&&r(n,e)}render(){return this.state.hasError?null:this.props.children}}const d=window.wp.primitives,m=(0,r.createElement)(d.SVG,{xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 24 24"},(0,r.createElement)(d.Path,{d:"M10.5 4v4h3V4H15v4h1.5a1 1 0 011 1v4l-3 4v2a1 1 0 01-1 1h-3a1 1 0 01-1-1v-2l-3-4V9a1 1 0 011-1H9V4h1.5zm.5 12.5v2h2v-2l3-4v-3H8v3l3 4z"})),v={};function f(e,n){if("object"!=typeof n)return console.error("No settings object provided!"),null;if("string"!=typeof e)return console.error("Plugin name must be string."),null;if(!/^[a-z][a-z0-9-]*$/.test(e))return console.error('Plugin name must include only lowercase alphanumeric characters or dashes, and start with a letter. Example: "my-plugin".'),null;v[e]&&console.error(`Plugin "${e}" is already registered.`),n=(0,o.applyFilters)("plugins.registerPlugin",n,e);const{render:r,scope:t}=n;if("function"!=typeof r)return console.error('The "render" property must be specified and must be a valid function.'),null;if(t){if("string"!=typeof t)return console.error("Plugin scope must be string."),null;if(!/^[a-z][a-z0-9-]*$/.test(t))return console.error('Plugin scope must include only lowercase alphanumeric characters or dashes, and start with a letter. Example: "my-page".'),null}return v[e]={name:e,icon:m,...n},(0,o.doAction)("plugins.pluginRegistered",n,e),n}function w(e){if(!v[e])return void console.error('Plugin "'+e+'" is not registered.');const n=v[e];return delete v[e],(0,o.doAction)("plugins.pluginUnregistered",n,e),n}function h(e){return v[e]}function y(e){return Object.values(v).filter((n=>n.scope===e))}const x=function(e,n){var r,t,o=0;function i(){var i,l,s=r,u=arguments.length;e:for(;s;){if(s.args.length===arguments.length){for(l=0;l<u;l++)if(s.args[l]!==arguments[l]){s=s.next;continue e}return s!==r&&(s===t&&(t=s.prev),s.prev.next=s.next,s.next&&(s.next.prev=s.prev),s.next=r,s.prev=null,r.prev=s,r=s),s.val}s=s.next}for(i=new Array(u),l=0;l<u;l++)i[l]=arguments[l];return s={args:i,val:e.apply(null,i)},r?(r.prev=s,s.next=r):t=s,o===n.maxSize?(t=t.prev).next=null:o++,r=s,s.val}return n=n||{},i.clear=function(){r=null,t=null,o=0},i}(((e,n)=>({icon:e,name:n})));const P=function({scope:e,onError:n}){const i=(0,t.useMemo)((()=>{let n=[];return{subscribe:e=>((0,o.addAction)("plugins.pluginRegistered","core/plugins/plugin-area/plugins-registered",e),(0,o.addAction)("plugins.pluginUnregistered","core/plugins/plugin-area/plugins-unregistered",e),()=>{(0,o.removeAction)("plugins.pluginRegistered","core/plugins/plugin-area/plugins-registered"),(0,o.removeAction)("plugins.pluginUnregistered","core/plugins/plugin-area/plugins-unregistered")}),getValue(){const r=y(e);return l()(n,r)||(n=r),n}}}),[e]),s=(0,t.useSyncExternalStore)(i.subscribe,i.getValue);return(0,r.createElement)("div",{style:{display:"none"}},s.map((({icon:e,name:t,render:o})=>(0,r.createElement)(a,{key:t,value:x(e,t)},(0,r.createElement)(g,{name:t,onError:n},(0,r.createElement)(o,null))))))};(window.wp=window.wp||{}).plugins=n})();