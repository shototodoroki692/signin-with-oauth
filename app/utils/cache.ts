/* 
* Ce fichier nous permet d'intéragir avec le cache afin que ce dernier puisse
* être utilisé par notre application, quelle soit native ou sur le web.
*/

import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

type TokenCache = {
    getToken: (key: string) => Promise<string | null>;
    saveToken: (key: string, token: string) => Promise<void>;
    deleteToken: (key: string) => Promise<void>;
};

const createTokenCache = (): TokenCache => {
    return {
        getToken: async (key: string) => {
            try {
                const item = await SecureStore.getItemAsync(key)
                if (!item) {
                    console.log("Aucune session n'est sauvegardé en cache");
                } else {
                    console.log("Session récupérée depuis le cache");
                }
                return item;
            } catch(e) {
                await SecureStore.deleteItemAsync(key);
                return null;
            }
        },
        saveToken: async (key: string, token: string) => {
            return SecureStore.setItemAsync(key, token)
        },
        deleteToken: async (key: string) => {
            return SecureStore.deleteItemAsync(key);
        },
    };
};

// si la plateforme utilisée par le client est le web, nous renvoyons un gestionnaire
// de cache pour les tokens "undefined" afin d'éviter d'utiliser le module natif
// expo-secure-store dans le web, ce qui causerait des problèmes d'exécution.
export const tokenCache = Platform.OS === "web" ? undefined : createTokenCache();