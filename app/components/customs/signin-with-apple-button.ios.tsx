import { useAuth } from "@/context/auth";
import * as AppleAuthentication from "expo-apple-authentication";
import { StyleSheet, useColorScheme } from "react-native"

export function SignInWithAppleButton() {
    const { signInWithApple } = useAuth();
    const theme = useColorScheme();

    return (
        <AppleAuthentication.AppleAuthenticationButton
            buttonType={AppleAuthentication.AppleAuthenticationButtonType.SIGN_IN} 
            buttonStyle={AppleAuthentication.AppleAuthenticationButtonStyle.WHITE}
            cornerRadius={5}
            style={styles.button}
            onPress={signInWithApple}
        />
    );
}

const styles = StyleSheet.create({
  button: {
    width: '100%',
    height: 50,
  },
});