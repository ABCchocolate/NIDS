from scapy.all import *
from tensorflow import keras
import numpy as np

# Load the machine learning model from the h5 file
model = keras.models.load_model("model.h5")

# Define a function to capture packets
def capture_packets(packet_count):
    # Capture the specified number of packets
    packets = sniff(count=packet_count)

    # Process each packet
    for packet in packets:
        # Print the packet summary
        print(packet.summary())

        # Extract the packet features
        packet_features = np.array([len(packet), packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport])

        # Use the machine learning model to predict if the packet is malicious or benign
        prediction = model.predict(packet_features)

        # Print the prediction
        if prediction > 0.5:
            print("Malicious packet detected!")
        else:
            print("Benign packet.")