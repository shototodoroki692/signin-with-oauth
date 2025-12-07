/*
*  Ce contexte permet de gérer toute la logique d'authentification
*  de l'application.
*/

import * as React from "react";
import * as WebBrowser from "expo-web-browser";
import { AuthError, AuthRequestConfig, DiscoveryDocument, makeRedirectUri, useAuthRequest } from "expo-auth-session";
import { BACKEND_BASE_URL } from "@/constants";


WebBrowser.maybeCompleteAuthSession();

export type AuthUser = {
    id: string;
    email: string;
    name: string;
    picture?: string;
    given_name?: string;
    family_name?: string;
    email_verified?: boolean;
    provider?: string;
    exp?: number;
    cookieExpiration?: number; // ajouté pour le suivi de l'expiration des cookies sur le web
};

const AuthContext = React.createContext({
    // valeurs par défaut
    user: null as AuthUser | null,
    signIn: () => {},
    signOut: () => {},
    fetchWithAuth: async (url: string, options?: RequestInit) => Promise.resolve(new Response()),
    isLoading: false,
    error: null as AuthError | null,
});

const config: AuthRequestConfig = {
    clientId: "google",
    scopes: ["openid", "profile", "email"],
    redirectUri: makeRedirectUri(),
};

// Notre flow OAuth utilise une approche server-side pour améliorer la sécurité:
// 1. Le client initie le flow OAuth avec Google à travers notre serveur
// 2. Google redirige vers le endpoint de notre API: /auth/authorize
// 3. Notre serveur traite le flow OAuth avec Google en utilisant des crédentials côté serveur
// 4. Le client reçoit un code d'autorisation depuis notre serveur d'API
// 5. Le client échange son code d'autorisation pour obtenirs ses tokens par notre API
// 6. Notre serveur d'API utilise ses crédentials pour obtenir les tokens
//    fournis par Google et nous renvoi ses propres tokens d'autorisation (JWT)
const discovery: DiscoveryDocument = {
    // L'URL vers laquelle les utilisateurs sont redirigés pour se connecter
    // et obtenir leur autorisation.
    // Notre serveur d'API traite le flow OAuth avec Google et nous renvoi
    // le code d'autorisation de Google
    authorizationEndpoint: `${BACKEND_BASE_URL}/auth/authorize`,
    // L'URL vers laquelle notre serveur d'API échange notre code d'autorisation
    // contre ses propres tokens d'autorisation.
    // Notre serveur d'API utilise ses propres crédentials (client ID et secret)
    // pour échanger de manière sécurisée notre code d'autorisation avec Google
    // et renvoyer les tokens d'autorisation au client
    tokenEndpoint: `${BACKEND_BASE_URL}/auth/token`,
};

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {

    const [user, setUser] = React.useState<AuthUser | null>(null);
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState<AuthError | null>(null);

    const [request, response, promptAsync] = useAuthRequest(config, discovery);

    React.useEffect(() => {
        // débug
        console.log("réponse reçue de la requête d'authentification:\n", response)

        handleResponse();
    }, [response]);

    // handleResponse permet de traiter la réponse renvoyée suite à une demande d'authentification
    const handleResponse = async () => {
        if (response?.type === "success") {

            // récupérer le code d'autorisation Google
            const { code } = response.params;
            console.log("code d'autorisation Google reçu:\n", code);

        } else if (response?.type === "error") {
            setError(response.error as AuthError);
        }
    }

    // signIn permet d'envoyer une demande de connexion avec Google
    const signIn = async () => {
        // débug
        console.log("demande de connexion avec Google")

        try {
            if (!request) {
                console.log("aucune requête configurée");
                return;
            }

            await promptAsync();
        } catch(e) {
            console.log(e);
        }
    };

    const signOut = async () => {};

    const fetchWithAuth = async (url: string, options?: RequestInit) => {};

    return (
        <AuthContext.Provider value={{
            user,
            signIn,
            signOut,
            fetchWithAuth,
            isLoading,
            error,
        }}>
            {children}
        </AuthContext.Provider>
    );
};

// hook permet d'accéder au contexte
export const useAuth = () => {
    const context = React.useContext(AuthContext);
    if (!context) {
        throw new Error("useAuth doit être utilisé dans un AuthProvider")
    }
    return context;
}