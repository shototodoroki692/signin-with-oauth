import { Pressable, View, Image } from "react-native";
import { ThemedText } from "../themed-text";

export default function SignInWithGoogleButton({
  onPress,
  disabled,
}: {
  onPress: () => void;
  disabled?: boolean;
}) {
  return (
    <Pressable onPress={onPress} disabled={disabled} style={{width: '100%'}}>
      <View
        style={{
          width: "100%",
          height: 50,
          flexDirection: "row",
          alignItems: "center",
          justifyContent: "center",
          borderRadius: 5,
          backgroundColor: "#fff",
          borderWidth: 1,
          borderColor: "#ccc",
        }}
      >
        <Image
          source={require("../../assets/images/google-icon.png")}
          style={{
            width: 20,
            height: 20,
            marginRight: 6,
          }}
        />
        <ThemedText type="defaultSemiBold" darkColor="#000" style={{fontSize:19}}>
          Se connecter avec Google
        </ThemedText>
      </View>
    </Pressable>
  );
}