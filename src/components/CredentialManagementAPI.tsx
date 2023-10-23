"use client";

import { useState } from "react";
import { useMount } from "@/hooks/useMount";

export function CredentialManagementAPI() {
  const [displayContent, setDisplayContent] = useState("");

  const mounted = useMount();
  if (!mounted) return null;

  return (
    <>
      <h1>CredentialManagementAPI</h1>
      <pre>Credential: {displayContent}</pre>
      <button
        className="block"
        onClick={() => {
          // @ts-ignore
          const credential = new PasswordCredential({
            type: "password",
            id: "hello_there_is_an_apple_tree",
            password: "test",
          });

          navigator.credentials
            .store(credential)
            .then(() => {
              console.log("Credential stored");
            })
            .catch((err) => {
              console.log("Credential not stored");
            });
        }}
      >
        Create & Store Password Credential
      </button>
      <button
        className="block"
        onClick={async () => {
          const credential = await navigator.credentials.get({
            // @ts-ignore
            password: true,
            id: "hello_there_is_an_apple_tree",
          });

          setDisplayContent(JSON.stringify(credential));
        }}
      >
        Get Credienal
      </button>
    </>
  );
}
