import Keycloak from "keycloak-js";

const keycloak = new Keycloak({
  url: import.meta.env.VITE_KEYCLOAK_URL ?? "https://sso.example.com",
  realm: import.meta.env.VITE_KEYCLOAK_REALM ?? "aac",
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID ?? "aac-portal",
});

export default keycloak;
