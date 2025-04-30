import { Link } from "react-router-dom";

const Sidebar = () => {
  return (
    <div className="w-64 bg-gray-800 text-white min-h-screen p-5">
      <h2 className="text-xl font-bold mb-6">SecureDocs</h2>
      <nav className="space-y-4">
        <Link to="/dashboard" className="block px-3 py-2 rounded hover:bg-gray-700">Dashboard</Link>
        <Link to="/upload" className="block px-3 py-2 rounded hover:bg-gray-700">Upload</Link>
        <Link to="/sent" className="block px-3 py-2 rounded hover:bg-gray-700">Sent Documents</Link>
        <Link to="/received" className="block px-3 py-2 rounded hover:bg-gray-700">Received Documents</Link>
      </nav>
    </div>
  );
};

export default Sidebar;
