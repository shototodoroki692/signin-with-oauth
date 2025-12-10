/*
*  Ce contexte permet de gérer toute la logique d'authentification
*  de l'application.
*/

import * as React from "react";
import * as jose from 'jose';
import * as WebBrowser from "expo-web-browser";
import { 
    AuthError, 
    AuthRequestConfig, 
    DiscoveryDocument, 
    exchangeCodeAsync, 
    makeRedirectUri, 
    useAuthRequest 
} from "expo-auth-session";
import { ACCESS_TOKEN_NAME, BACKEND_BASE_URL } from "@/constants";
import { Platform } from "react-native";
import { tokenCache } from "@/utils/cache";


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
    const [accessToken, setAccessToken] = React.useState<string | null>(null);

    const [request, response, promptAsync] = useAuthRequest(config, discovery);
    const isWeb = Platform.OS === "web";

    React.useEffect(() => {
        // débug
        console.log("réponse reçue de la requête d'authentification:\n", response)

        handleResponse();
    }, [response]);

    // handleResponse permet de traiter la réponse renvoyée suite à une demande d'authentification
    const handleResponse = async () => {
        if (response?.type === "success") {
            try {
                setIsLoading(true);

                // échanger le code d'autorisation Google avec les tokens d'autorisation de notre backend:
                //
                // La requête envoyée en fond atteindra notre endpoint /auth/token
                //
                // ATTENTION:
                // Le contenu du corps de la requête n'est pas du json mais x-www-form-urlencoded
                //
                // NOTE:
                // Il est possible d'effectuer la requête avec un fetch classique
                // envoyant le code d'autorisation Google dans le body. Mais ici 
                // nous utilisons déjà la bibliothèque expo-auth-session, donc nous
                // en utilisons les fonctions.
                //
                // Voici comment faire:

                // récupérer le code d'autorisation Google
                const { code } = response.params;

                // créer un formulaire de données pour envoyer à notre endpoint /auth/token
                const formData = new FormData();
                formData.append("code", code);

                // préciser au serveur si le client est un client web.
                // (par défaut, le serveur considère que le client est une plateform native)
                if (isWeb) {
                    formData.append("platform", "web")
                }

                // envoyer notre code d'autorisation à notre endpoint /auth/token
                // Le serveur va échanger ce code pour obtenir en retour les tokens d'autorisation
                // (access et refresh token) de notre serveur.
                //
                // NOTE:
                // client natif: les tokens sont contenus directement dans la réponse
                const tokenResponse = await fetch(`${BACKEND_BASE_URL}/auth/token`, {
                    method: "POST",
                    body: formData,
                    credentials: isWeb ? "include" : "same-origin",
                });

                // Voici la manière d'envoyer la requête en utilisant la bibliothèque 
                // expo-auth-session
                // 
                // const tokenResponse = await exchangeCodeAsync(
                //     {
                //         extraParams: {
                //             platform: Platform.OS,
                //         },
                //         clientId: "google",
                //         code: code,
                //         redirectUri: makeRedirectUri(),
                //     },
                //     discovery
                // );

                if (isWeb) {
                    const sessionResponse = await fetch(`${BACKEND_BASE_URL}/auth/session`, {
                        method: "GET",
                        credentials: "include",
                    });
                
                    if (sessionResponse.ok) {
                        const sessionData = await sessionResponse.json();
                        setUser(sessionData as AuthUser);
                    }
                } else {

                    //const accessToken = tokenResponse.accessToken;
                    const accessToken = await tokenResponse.json()
                    
                    // débug
                    console.log("access token:\n", accessToken)

                    setAccessToken(JSON.stringify(accessToken));

                    // enregistrer l'access token dans le local storage
                    tokenCache?.saveToken(ACCESS_TOKEN_NAME, accessToken);

                    // NOTE:
                    // Beto dans le tutoriel utilise la bibliothèque jose
                    // pour récupérer les informations de l'utilisateur depuis
                    // le token d'accès.
                    // 
                    // voici comment faire:
                    const decodedJwt = jose.decodeJwt(accessToken);
                    const googleJwt = decodedJwt.sub

                    // débug
                    console.log("decoded jwt:", decodedJwt)

                    // mettre l'utiliseur en tant que random pour le moment
                    // const connectedUser = {
                    //     id: "random",
                    //     email: "random email",
                    //     name: "beto ramos",
                    // } as AuthUser;

                    setUser(decodedJwt as AuthUser);
                }
            } catch(e) {
                console.log("erreur:", e)
            } finally {
                setIsLoading(false);
            }

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