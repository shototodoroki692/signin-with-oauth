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
import * as AppleAuthentication from "expo-apple-authentication";
import { randomUUID } from "expo-crypto"
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
    signInWithApple: () => {},
    signInWithAppleWebBrowser: () => {},
    fetchWithAuth: (url: string, options: RequestInit) => Promise.resolve(new Response()),
    isLoading: false,
    error: null as AuthError | null,
});

// configuration de la requête d'authentification avec Google
const config: AuthRequestConfig = {
    clientId: "google",
    scopes: ["openid", "profile", "email"],
    redirectUri: makeRedirectUri(),
};

// configuration de la requête d'authentification avec Apple (inutile
// pour la configuration d'un client iOS seul)
const appleConfig: AuthRequestConfig = {
    clientId: "apple",
    scopes: ["name", "email"],
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

// discoveryDocument utilisé pour l'authentification avec Apple (inutile
// pour la configuration d'un client iOS seul)
const appleDiscovery: DiscoveryDocument = {
    authorizationEndpoint: `${BACKEND_BASE_URL}/auth/apple/authorize`,
    tokenEndpoint: `${BACKEND_BASE_URL}/auth/apple/token`,
};

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {

    const [user, setUser] = React.useState<AuthUser | null>(null);
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState<AuthError | null>(null);
    const [accessToken, setAccessToken] = React.useState<string | null>(null);

    // configuration de la requête d'authentification avec Apple (inutile
    // lors de l'utilisation d'un client iOS seul)
    const [appleRequest, appleResponse, promptAppleAsync] = useAuthRequest(appleConfig, appleDiscovery);

    // configuration de la requête d'authentification avec Google
    const [request, response, promptAsync] = useAuthRequest(config, discovery);

    const isWeb = Platform.OS === "web";

    // traitement de la réponse reçue après l'appel de promptAsync dans signIn
    React.useEffect(() => {
        // débug
        console.log("réponse reçue de la requête d'authentification avec Google:\n", response)

        handleResponse();
    }, [response]);

    // traitement de la réponse reçue après l'appel de promptAppleAsync dans le
    // signInWithApple.
    React.useEffect(() => {
        // débug
        console.log("réponse reçue de la requête d'authentification avec Apple:\n", appleResponse)

        handleAppleResponse();
    }, [appleResponse]);

    // restaurer la session de l'utilisateur dès qu'il rafraîchit sa page web
    // Cela ne fonctionne que si le cookie est encore valide au moment du
    // rafraîchissement de la page
    React.useEffect(() => {
        const restoreSession = async () => {
            setIsLoading(true);
            try {
                if (isWeb) {
                    const sessionResponse = await fetch(`${BACKEND_BASE_URL}/auth/session`, {
                        method: "GET",
                        credentials: "include" // inclu le cookie dans la requête
                    });

                    if (sessionResponse.ok) {
                        const userData = await sessionResponse.json();
                        setUser(userData as AuthUser);
                    }
                } else {
                    // Pour les clients natifs, essayer d'abord d'utiliser l'access token
                    // mis dans le store
                    const storedAccessToken = await tokenCache?.getToken(ACCESS_TOKEN_NAME);

                    if (storedAccessToken) {
                        try {
                            const decoded = jose.decodeJwt(storedAccessToken);

                            // vérifier si l'accesstoken a expiré
                            const exp = (decoded as any).exp;
                            const now = Math.floor(Date.now() / 1000);

                            if (exp && exp > now) {

                                // le token d'accès est encore valide
                                setAccessToken(storedAccessToken);
                                setUser(decoded as AuthUser);
                            } else {
                                // récupérer le refresh token si besoin (il n'y en a pas
                                // dans cette application de démo)

                                setUser(null);
                                tokenCache?.deleteToken(ACCESS_TOKEN_NAME);
                            }
                        } catch(e) {
                            console.log("erreur ce mise à jour de l'accès token:\n", e);
                        }
                    }
                }
            } catch(e) {
                console.log("erreur lors de la restauration de la session de l'utilisateur:\n", e)
            } finally {
                setIsLoading(false)
            }
        }
        restoreSession();
    }, [isWeb]);

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

                // récupérer le code verifier de la requête
                // Il s'agit du même verifier que celui utilisé pour générer le challenge pour le code
                if (request?.codeVerifier) {
                    formData.append("code_verifier", request.codeVerifier);
                } else {
                    console.warn("aucun code verifier n'a été trouvé dans la requête")
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
                    // Pour le web, le serveur met le token dans un cookie http-only
                    // Nous avons juste à récupérer les données de l'utilisateur dans la reponse
                    const userData = await tokenResponse.json();

                    if(userData.success) {
                        // débug
                        console.log("demande des informations de session")

                        // récupérer la session pour obtenir les données de l'utilisateur
                        // Cela assure que nous avons les dernières informations mise à jour.
                        const sessionResponse = await fetch(`${BACKEND_BASE_URL}/auth/session`, {
                            method: "GET",
                            credentials: "include",
                        });

                        // ATTENTION:
                        // j'ai l'erreur suivante dans mon navigateur une fois le fetch
                        // réalisé:
                        // has been blocked by CORS policy: No 'Access-Control-Allow-Origin'
                        //
                        // Pour l'instant je ne m'en occupe pas car elle concerne les 
                        // clients web uniquement 

                        if (sessionResponse.ok) {
                            const sessionData = await sessionResponse.json();

                            // débug
                            console.log("sessionData:\n", sessionData)

                            setUser(sessionData as AuthUser);
                        }
                    }
                } else {

                    //const accessToken = tokenResponse.accessToken;
                    const accessToken = await tokenResponse.json()
                    
                    // débug
                    console.log("access token:\n", accessToken);
                    console.log("access token (stringified):", JSON.stringify(accessToken))

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

    // handleAppleResponse permet de traiter la réponse renvoyée suite à une demande d'authentification
    // avec Apple (inutile pour un client iOS seul)
    const handleAppleResponse = async () => {
        if (appleResponse?.type === "success") {
            try {
                // // échanger le code d'autorisation Google avec les tokens d'autorisation de notre backend:
                // //
                // // La requête envoyée en fond atteindra notre endpoint /auth/token
                // //
                // // ATTENTION:
                // // Le contenu du corps de la requête n'est pas du json mais x-www-form-urlencoded
                // //
                // // NOTE:
                // // Il est possible d'effectuer la requête avec un fetch classique
                // // envoyant le code d'autorisation Google dans le body. Mais ici 
                // // nous utilisons déjà la bibliothèque expo-auth-session, donc nous
                // // en utilisons les fonctions.
                // //
                // // Voici comment faire:

                // // récupérer le code d'autorisation Google
                // const { code } = response.params;

                // // créer un formulaire de données pour envoyer à notre endpoint /auth/token
                // const formData = new FormData();
                // formData.append("code", code);

                // // préciser au serveur si le client est un client web.
                // // (par défaut, le serveur considère que le client est une plateform native)
                // if (isWeb) {
                //     formData.append("platform", "web")
                // }

                // // récupérer le code verifier de la requête
                // // Il s'agit du même verifier que celui utilisé pour générer le challenge pour le code
                // if (request?.codeVerifier) {
                //     formData.append("code_verifier", request.codeVerifier);
                // } else {
                //     console.warn("aucun code verifier n'a été trouvé dans la requête")
                // }

                // // envoyer notre code d'autorisation à notre endpoint /auth/token
                // // Le serveur va échanger ce code pour obtenir en retour les tokens d'autorisation
                // // (access et refresh token) de notre serveur.
                // //
                // // NOTE:
                // // client natif: les tokens sont contenus directement dans la réponse
                // const tokenResponse = await fetch(`${BACKEND_BASE_URL}/auth/token`, {
                //     method: "POST",
                //     body: formData,
                //     credentials: isWeb ? "include" : "same-origin",
                // });

                // Voici la manière d'envoyer la requête en utilisant la bibliothèque 
                // expo-auth-session

                const { code } = appleResponse.params;
                
                const response = await exchangeCodeAsync(
                    {
                        clientId: "apple",
                        code,
                        redirectUri: makeRedirectUri(),
                        extraParams: {
                            platform: Platform.OS,
                        },
                    },
                    appleDiscovery
                );

                // débug
                console.log("réponse de /auth/apple/callback:", response)

                if (isWeb) {
                    // Pour le web, le serveur met le token dans un cookie http-only
                    // Nous avons juste à récupérer les données de l'utilisateur dans la reponse

                    // débug
                    console.log("demande des informations de session")

                    // récupérer la session pour obtenir les données de l'utilisateur
                    // Cela assure que nous avons les dernières informations mise à jour.
                    const sessionResponse = await fetch(`${BACKEND_BASE_URL}/auth/session`, {
                        method: "GET",
                        credentials: "include",
                    });

                    // ATTENTION:
                    // j'ai l'erreur suivante dans mon navigateur une fois le fetch
                    // réalisé:
                    // has been blocked by CORS policy: No 'Access-Control-Allow-Origin'
                    //
                    // Pour l'instant je ne m'en occupe pas car elle concerne les 
                    // clients web uniquement 

                    if (sessionResponse.ok) {
                        const sessionData = await sessionResponse.json();

                        // débug
                        console.log("sessionData:\n", sessionData);

                        setUser(sessionData as AuthUser);
                    }
                } else {
                    // RAPPEL:
                    // Ce bloc ne concerne que les clients android.
                    // Le client iOS (l'autre type de client natif) étant traité dans
                    // la fonction signInWithApple.
                    await handleNativeTokens({
                        accessToken: response.accessToken,
                        refreshToken: "", // nous ne renvoyons pas de refresh token pour l'instant
                    });
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

    // signInWithApple permet de s'authentifier avec son compte Apple lorsque 
    // l'utilisateur est sur un client ios
    const signInWithApple = async () => {

        // débug
        console.log("tentative de connexion avevc Apple depuis un appareil ios");

        try {
            const rawNonce = randomUUID();

            // renvoi les informations de l'utiliseur
            const credential = await AppleAuthentication.signInAsync({
                requestedScopes: [
                AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
                AppleAuthentication.AppleAuthenticationScope.EMAIL,
                ],
                nonce: rawNonce,
            });
            // signed in

            // débug
            console.log("credentials récupérés:\n", credential)

            if (credential.fullName?.givenName && credential.email) {
                // Ces informations indiquent qu'il s'agit de la première
                // connexion de l'utilisateur avec Apple.
                // Il s'agit de notre seule chance d'obtenir le nom et l'email
                // de l'utilisateur.
                // Nous devons stocker ces informations dans notre base de données
                // Nous pouvons également traiter cela côté serveur. Il faut juste 
                // garder en tête qu'Apple fournit le nom et l'email de l'utilisateur
                // uniquement à la première connexion de ce dernier. Ces champs seront
                // null lors des prochaines connexions de l'utilisateur avec Apple.
                console.log("Première connexion de l'utilisateur avec Apple");
            }

            // envoyer l'identity token et le code d'autorisation à notre backend
            const appleResponse = await fetch(`${BACKEND_BASE_URL}/auth/apple/ios`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    identity_token: credential.identityToken,
                    raw_nonce: rawNonce, // Utiliser le nonce que nous avons généré et transmis à Apple

                    // IMPORTANT:
                    // Apple fournit uniquement le nom et l'email lors de la première connexion.
                    // Lors des connexions suivantes, ces champs seront null.
                    // Nous devons stocker les informations de l'utilisateur fournies lors de sa
                    // première connexion dans notre base de données, et récupérer ces informations
                    // lors des prochaines connexions en utilisant l'identifiant utilisateur stable
                    given_name: credential.fullName?.givenName,
                    family_name: credential.fullName?.familyName,
                    email: credential.email,
                }),
            });

            // si appleResponse est ok, stocker les tokens d'accès dans le local storage
            const tokens = await appleResponse.json();
            await handleNativeTokens(tokens);

        } catch (e) {
            // débug
            console.log("erreur survenue lors de l'authentification avec apple");
        }
    };

    // signInWithAppleWebBrowser permet de s'authentifier avec son compte Apple
    // lorsque l'utilisateur est sur un client web ou android
    const signInWithAppleWebBrowser = async () => {
        try {
            if (!appleRequest) {
                console.log("appleRequest null");
                return;
            }
            await promptAppleAsync();
        } catch (e) {
            console.log("erreur survenue lors de l'authentification avec Apple sur un client web:\n", e)
        }
    };

    // handleNativeTokens permet de traiter la réception des tokens d'autorisation
    // renvoyés par notre backend après l'authentification de l'utilisateur avec Apple
    const handleNativeTokens = async (tokens: {
        accessToken: string;
        refreshToken: string;
    }) => {
        const { accessToken: newAccessToken, refreshToken: newRefreshToken } = tokens;

        console.log("access token initial reçu:", newAccessToken ? "présent" : "manquant");
        console.log("refresh token initial reçu:", newRefreshToken ? "présent" : "manquant");

        // stocker les tokens dans les états
        if (newAccessToken) setAccessToken(newAccessToken);
        // if (newRefreshToken) setRefreshToken(newRefreshToken); // à ajouter lorsque nous utiliserons un refresh token
    
        // Stocker les tokens dans le secure storage
        if (newAccessToken) 
            await tokenCache?.saveToken("accessToken", newAccessToken);

        // à ajouter lorsque nous utiliserons les refresh tokens
        // if (newRefreshToken)
        //     await tokenCache?.saveToken("refreshToken", newRefreshToken)

        // décoder l'access token pour obtenir les informations de l'utilisateur
        if (newAccessToken) {
            const decodedAccessToken = jose.decodeJwt(newAccessToken);
            setUser(decodedAccessToken as AuthUser);
        }
    }

    // déconnecter l'utilisateur
    const signOut = async () => {
        if (isWeb) {
            // Client Web: Appeler l'endpoint signout pour retirer le cookie
            try {
                await fetch(`${BACKEND_BASE_URL}/auth/signout`, {
                    method: "POST",
                    credentials: "include",
                });
            } catch (e) {
                console.log("erreur lors de la déconnexion côté serveur:", e);
            }
        } else {
            // Client natif: Retirer les tokens d'autorisation du cache
            // 
            // (dans notre cas uniquement l'access token)    
            await tokenCache?.deleteToken(`${ACCESS_TOKEN_NAME}`)
        }

        // modifier les états
        setUser(null);
        setAccessToken("");
    };

    // fetchWithAuth de récupérer des données protégées de notre backend
    const fetchWithAuth = async (url: string, options: RequestInit) => {

        // débug
        console.log("demande de fetch avec les données d'authentification")
        console.log("url:", url)

        if (isWeb) {
            // pour le web: inclure les credentials pour envoyer nos cookies
            const response = await fetch(url, {
                ...options,
                credentials: "include",
            });

            // si la réponse renvoie une erreur d'autorisation, essayer de
            // rafraîchir notre token d'accès
            if (response.status === 401) {
                console.log("Erreur 401: Unauthorized. Rafraichissez votre token d'accès")

                // Tentative de rafraîchissement de l'access token
                // si nous possédons un refresh token

                // retenter le fetch si nous avons reçu un nouvel
                // access token
            }

            return response;
        } else {
            // débug
            console.log("client sur plateforme native");
            console.log("access token:\n", accessToken)
            console.log("access token (parsé):\n", JSON.parse(accessToken!))

            // Pour un client natif: inclure l'access token dans Authorization header
            const response = await fetch(url, {
                ...options,
                headers: {
                    ...options.headers,
                    Authorization: `Bearer ${JSON.parse(accessToken!)}`,
                },
            });

            // débug
            console.log("réponse reçue:\n", response)

            // traiter les réponses avec le status 401 en tentant de refraîchir
            // l'accès token si nous avons un refresh token

            return response;
        }
    };

    return (
        <AuthContext.Provider value={{
            user,
            signIn,
            signOut,
            signInWithApple,
            signInWithAppleWebBrowser,
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