/*
*  Ce fichier nous permet de sotcker les constantes utilisées
*  dans notre application
* 
*  Ces constantes seront à utiliser dans le backend, c'est juste pour 
*  copier le tutoriel pour l'instant
*/

// Constantes liées à notre serveur de backend
export const LAN_BACKEND_IP_ADDR = process.env.EXPO_PUBLIC_LAN_BACKEND_IP_ADDR;
export const BACKEND_BASE_URL = `http://${LAN_BACKEND_IP_ADDR}:3000`;

// Constantes d'authentification
export const ACCESS_TOKEN_NAME = "access_token";
export const REFRESH_TOKEN_NAME = "session_token";
export const ACCESS_TOKEN_MAX_AGE = 20; // 20 secondes
export const SESSION_TOKEN_MAX_AGE = 30 * 25 * 60 * 60 // 30 jours en secondes
export const ACCESS_TOKEN_LIFETIME = "20s"; // 20 secondes
export const SESSION_TOKEN_LIFETIME = "30d"; // 30 jours

// Constantes d'environnement
export const BASE_URL = process.env.EXPO_PUBLIC_BASE_URL;
export const APP_SCHEME = process.env.EXPO_PUBLIC_SCHEME;
export const JWT_SECRET = process.env.JWT_SECRET

// Paramètres des cookies
export const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: true,
    sameSite: "Lax" as const,
    path: "/",
    maxAge: ACCESS_TOKEN_MAX_AGE,
};

export const SESSION_COOKIE_OPTIONS = {
    httpOnly: true,
    secure: true,
    sameSite: "Lax" as const,
    path: "/auth/refresh",
    maxAge: SESSION_TOKEN_MAX_AGE,
};