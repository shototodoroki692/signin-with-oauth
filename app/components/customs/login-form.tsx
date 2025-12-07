/*
*  Ce formulaire permet à l'utilisateur de se connecter
*/

import { useAuth } from "@/context/auth";
import { View, Text, Button, StyleSheet } from "react-native";
import * as AppleAuthentication from 'expo-apple-authentication'

export default function LoginForm() {
    // importer les méthodes du hook d'authentification
    const { signIn } = useAuth();

    return (
        <View style={styles.signInView}>
            <Text style={styles.text}>Se connecter</Text>

            {/* Bouton de connexion avec Google */}
            <Button title="Se connecter avec Google" onPress={signIn} />
            
            {/* Bouton de connexion avec Apple */}
            <View style={styles.container}>
              <AppleAuthentication.AppleAuthenticationButton
                buttonType={AppleAuthentication.AppleAuthenticationButtonType.SIGN_IN} 
                buttonStyle={AppleAuthentication.AppleAuthenticationButtonStyle.WHITE}
                cornerRadius={5}
                style={styles.button}
                onPress={async () => {
                  try {
                    const credential = await AppleAuthentication.signInAsync({
                      requestedScopes: [
                        AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
                        AppleAuthentication.AppleAuthenticationScope.EMAIL,
                      ],
                    });
                    // signed in

                    // débug
                    console.log("credentials récupérés:\n", credential)

                  } catch (e) {
                    // débug
                    console.log("erreur survenue lors de l'authentification avec apple")
                  }
                }}
              />
            </View>
        </View>
    );
}

const styles = StyleSheet.create({
  signInView: {
    flex: 1,
    justifyContent: "center",
    alignItems: 'center',
    gap: 12,
  },
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    height: 50,
    width: '100%',
  },
  text: {
    color: "#ffffff"
  },
  button: {
    width: '100%',
    height: 50,
  },
});