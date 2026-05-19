import { useEffect } from 'react';
import { initBrowserSentinel } from '@/sentinel-sdk/browser/agent.ts';

// Initialize Sentinel Browser Agent (Presentation/Service layers)
initBrowserSentinel('Sentinel-Core-Library');

export default function App() {
  useEffect(() => {
    console.log("Sentinel SDK is active in the browser environment.");
  }, []);

  return null; // NO UI REQUIRED
}
