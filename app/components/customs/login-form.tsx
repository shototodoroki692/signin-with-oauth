/*
*  Ce formulaire permet à l'utilisateur de se connecter
*/

import { useAuth } from "@/context/auth";
import { View, Text, Button, StyleSheet } from "react-native";
import { SignInWithAppleButton } from "./signin-with-apple-button";
import SignInWithGoogleButton from "./signin-with-google-button";

export default function LoginForm() {
    // importer les méthodes du hook d'authentification
    const { signIn, isLoading } = useAuth();

    return (
        <View style={styles.signInView}>

            {/* Bouton de connexion avec Google */}
            <SignInWithGoogleButton onPress={signIn} disabled={isLoading} />
            
            {/* Bouton de connexion avec Apple */}
            <SignInWithAppleButton />
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
    backgroundColor: "#ae3f4e"
  },
  text: {
    color: "#ffffff"
  },
  button: {
    width: '100%',
    height: 50,
  },
});