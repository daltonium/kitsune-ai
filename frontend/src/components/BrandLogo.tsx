import React from "react";
import { Image, StyleSheet, View } from "react-native";

type Props = {
  size?: number;
};

export function BrandLogo({ size = 128 }: Props) {
  return (
    <View
      style={[
        styles.container,
        {
          width: size,
          height: size,
        },
      ]}
    >
      <Image
        source={require("../../assets/kitsune-logo.png")}
        accessibilityLabel="KITSUNE AI logo"
        resizeMode="contain"
        style={styles.image}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    alignSelf: "center",
    backgroundColor: "#050505",
    borderRadius: 12,
    overflow: "hidden",
  },
  image: {
    width: "100%",
    height: "100%",
  },
});