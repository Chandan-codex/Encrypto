// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getAnalytics } from "firebase/analytics";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBaGnLQtJDYGC7TGkw_D_41_rVQHXweE0w",
  authDomain: "encrypto-ad64a.firebaseapp.com",
  projectId: "encrypto-ad64a",
  storageBucket: "encrypto-ad64a.firebasestorage.app",
  messagingSenderId: "777763335662",
  appId: "1:777763335662:web:bfcae7f3292cd56cedf2ff",
  measurementId: "G-D70GVJYL8Y"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);

// Initialize Auth and Export for use in App.jsx
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();
