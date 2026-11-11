import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { pageBase } from "./base";
import { FilterProvider } from "./filters";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("root missing");

createRoot(root).render(
  <StrictMode>
    <BrowserRouter basename={pageBase(window.location.pathname) || "/"}>
      <FilterProvider>
        <App />
      </FilterProvider>
    </BrowserRouter>
  </StrictMode>,
);
