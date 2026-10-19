import { Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import Findings from './pages/Findings';
import Timeline from './pages/Timeline';
import SecurityActions from './pages/SecurityActions';
import PasswordTools from './pages/PasswordTools';
import ScanHistory from './pages/ScanHistory';
import DataSources from './pages/DataSources';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="scan" element={<NewScan />} />
        <Route path="findings" element={<Findings />} />
        <Route path="findings/:id" element={<Findings />} />
        <Route path="timeline" element={<Timeline />} />
        <Route path="actions" element={<SecurityActions />} />
        <Route path="tools" element={<PasswordTools />} />
        <Route path="history" element={<ScanHistory />} />
        <Route path="sources" element={<DataSources />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<div className="card">Page not found.</div>} />
      </Route>
    </Routes>
  );
}
