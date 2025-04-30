import Navbar from "../components/Navbar";

const Home = () => {
  return (
    <div>
      <div className="pt-20 flex flex-col items-center justify-center h-screen text-center">
        <h1 className="text-4xl font-bold text-gray-800">Welcome to SecureDocs</h1>
        <p className="text-gray-600 mt-4">Share documents securely with digital signatures.</p>
        <a href="/register" className="mt-6 px-6 py-2 bg-blue-600 text-white rounded-md">Lets Go!</a>
      </div>
    </div>
  );
};

export default Home;
