import "../styles/globals.css";
import "../styles/repository.css";
import "../styles/sandbox.css";
import "../styles/upload.css";
import "../styles/test-plan.css";
import type { AppProps } from "next/app";
export default function App({ Component, pageProps }: AppProps) { return <Component {...pageProps} />; }
