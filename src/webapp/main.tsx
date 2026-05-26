import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.js'
import './index.css'

const root = document.getElementById('root')
if (root === null) {
  throw new Error('#root element missing in index.html')
}
createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
