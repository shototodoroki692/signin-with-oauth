import { Image } from 'expo-image';
import { Text, StyleSheet, View, ActivityIndicator, Button } from 'react-native';

import * as AppleAuthentication from 'expo-apple-authentication'

import { HelloWave } from '@/components/hello-wave';
import ParallaxScrollView from '@/components/parallax-scroll-view';
import { ThemedText } from '@/components/themed-text';
import { ThemedView } from '@/components/themed-view';
import { Link } from 'expo-router';
import MessageContainer from '@/components/customs/message-container';
import { useEffect, useState } from 'react';
import * as Constants from "@/constants"
import { useAuth } from '@/context/auth';
import LoginForm from '@/components/customs/login-form';

// débug
console.log("LAN_BACKEND_IP_ADDR:", Constants.LAN_BACKEND_IP_ADDR);
console.log("BACKEND_DOMAIN_NAME:", Constants.BACKEND_BASE_URL);

export default function HomeScreen() {
  // importer les éléments du contexte d'authentification
  const { user, signOut, isLoading } = useAuth();

  // état du chargement de la page
  const [isPageLoading, setPageLoading] = useState<boolean>(false);

  // état du serveur API
  const [isBackendAvailable, setBackendAvailable] = useState<boolean>(false);

  // test d'accès au backend
  async function getBackendPublicEndpoint() {
    try {
      const response = await fetch(Constants.BACKEND_BASE_URL)
      response.status === 200 ? setBackendAvailable(true) : setBackendAvailable(false);

      // débug
      console.log("tentative d'accès au endpoint public de notre api:");
      console.log("status de la réponse:", response.status);
    } catch (e) {
      // débug
      console.log("erreur lors de la demande d'accès au endpoint public de notre api:\n", e);

      setBackendAvailable(false);
    } finally {
      setPageLoading(false);
    }
  }

  // test du serveur API
  useEffect(() => {
    getBackendPublicEndpoint();
  }, []);

  // Afficher une icône de chargement si la récupération de l'utilisateur 
  // est en cours
  if (isLoading) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center" }}>
        <ActivityIndicator />
      </View>
    )
  }

  return (
    <ParallaxScrollView
      headerBackgroundColor={{ light: '#A1CEDC', dark: '#1D3D47' }}
      headerImage={
        <Image
          source={require('@/assets/images/partial-react-logo.png')}
          style={styles.reactLogo}
        />
      }>

      {/* titre de la page */}
      <ThemedView style={styles.titleContainer}>
        <ThemedText type="title">Welcome!</ThemedText>
        <HelloWave />
      </ThemedView>

      {/* status de l'utilisateur */}
      <Text style={styles.text}>Utilisateur connecté: {JSON.stringify(user)}</Text>

      {/* Affichage du status du serveur */}
      <MessageContainer 
        message={isBackendAvailable ? 'Serveur backend disponible' : 'Serveur backend indisponible'}
        type={isBackendAvailable ? 'success' : 'error'}
      />

      {/* si l'utilisateur est connecté, afficher un bouton de déconnexion, sinon afficher le formulaire de connexion */}
      { user ? <Button title="Se déconnecter" onPress={() => signOut()} /> : <LoginForm />}
    </ParallaxScrollView>
  );
}

const styles = StyleSheet.create({
  titleContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  stepContainer: {
    gap: 8,
    marginBottom: 8,
  },
  reactLogo: {
    height: 178,
    width: 290,
    bottom: 0,
    left: 0,
    position: 'absolute',
  },
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  text: {
    color: "#ffffff",
  },
  button: {
    width: '100%',
    height: 50,
  },
});
