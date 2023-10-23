import { CredentialManagementAPI } from "@/components/CredentialManagementAPI";
import { WebAuthnAPI } from "@/components/WebAuthnAPI";

export default function Home() {
  return (
    <>
      <CredentialManagementAPI />
      <WebAuthnAPI />
    </>
  );
}
