import { Navigate, Route, Routes } from "react-router-dom";
import CiReviewOpsPage from "./pages/CiReviewOpsPage";
import HomePage from "./pages/HomePage";
import ProjectWorkbenchPage from "./pages/ProjectWorkbenchPage";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/reviewops" element={<CiReviewOpsPage />} />
      <Route path="/projects/:projectId" element={<ProjectWorkbenchPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
