
import joblib
from tensorflow.keras.models import load_model

# Load the model from the H5 file
weights_path = 'C:/Users/qrkdb/Documents/GitHub/NIDS/weight/cnn_model.h5'  # Path to the H5 file
model = load_model(weights_path)

# Save the model as a joblib file
save_path = 'C:/Users/qrkdb/Documents/GitHub/NIDS/weight/cnn_model.joblib'  # Desired path and filename for the joblib file
joblib.dump(model, save_path)
