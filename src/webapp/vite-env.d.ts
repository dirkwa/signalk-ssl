// TypeScript 6 stopped silently accepting side-effect imports for non-JS
// modules. Declare the file extensions Vite consumes so `import './x.css'`
// and friends typecheck cleanly.

declare module '*.css'
declare module '*.svg'
declare module '*.png'
declare module '*.jpg'
declare module '*.jpeg'
declare module '*.gif'
declare module '*.webp'
