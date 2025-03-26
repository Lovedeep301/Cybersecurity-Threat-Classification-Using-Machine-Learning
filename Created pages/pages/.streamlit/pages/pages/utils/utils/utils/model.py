import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

class ThreatDetectionModel:
    """
    Machine learning model for detecting cybersecurity threats in log data.
    """
    
    def __init__(self):
        """Initialize the model."""
        self.model = None
        self.preprocessor = None
        self.features = None
        self.model_type = 'random_forest'
        self.default_model_params = {
            'random_forest': {
                'n_estimators': 100,
                'max_depth': 10
            },
            'gradient_boosting': {
                'n_estimators': 100,
                'learning_rate': 0.1
            },
            'logistic_regression': {
                'C': 1.0,
                'max_iter': 100
            }
        }
    
    def _get_numeric_features(self, X):
        """Get numeric feature columns."""
        return X.select_dtypes(include=['int64', 'float64']).columns.tolist()
    
    def _get_categorical_features(self, X):
        """Get categorical feature columns."""
        return X.select_dtypes(include=['object', 'category']).columns.tolist()
    
    def _create_preprocessor(self, X):
        """Create a preprocessor for the data."""
        numeric_features = self._get_numeric_features(X)
        categorical_features = self._get_categorical_features(X)
        
        numeric_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='mean')),
            ('scaler', StandardScaler())
        ])
        
        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='most_frequent')),
            ('encoder', OneHotEncoder(handle_unknown='ignore'))
        ])
        
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, numeric_features),
                ('cat', categorical_transformer, categorical_features)
            ]
        )
        
        return preprocessor
    
    def _prepare_data(self, X):
        """Prepare data for model training or prediction."""
        # Select only feature columns, drop non-feature columns
        non_feature_cols = ['is_threat', 'threat_type']
        feature_cols = [col for col in X.columns if col not in non_feature_cols]
        
        # Return feature dataframe
        return X[feature_cols]
    
    def train(self, X, y, params=None):
        """
        Train the threat detection model.
        
        Args:
            X (pandas.DataFrame): Feature data
            y (pandas.Series): Target labels (1 for threat, 0 for non-threat)
            params (dict, optional): Model parameters
                - model_type: 'random_forest', 'gradient_boosting', or 'logistic_regression'
                - Other parameters specific to the chosen model type
        
        Returns:
            self: The trained model object
        """
        # Process parameters
        if params is None:
            params = {}
        
        # Set model type
        self.model_type = params.get('model_type', 'random_forest')
        
        # Prepare feature data
        X_features = self._prepare_data(X)
        self.features = X_features.columns.tolist()
        
        # Create preprocessor
        self.preprocessor = self._create_preprocessor(X_features)
        
        # Initialize model based on type
        if self.model_type == 'random_forest':
            model = RandomForestClassifier(
                n_estimators=params.get('n_estimators', 
                                        self.default_model_params['random_forest']['n_estimators']),
                max_depth=params.get('max_depth', 
                                    self.default_model_params['random_forest']['max_depth']),
                random_state=42
            )
        elif self.model_type == 'gradient_boosting':
            model = GradientBoostingClassifier(
                n_estimators=params.get('n_estimators', 
                                        self.default_model_params['gradient_boosting']['n_estimators']),
                learning_rate=params.get('learning_rate', 
                                        self.default_model_params['gradient_boosting']['learning_rate']),
                random_state=42
            )
        elif self.model_type == 'logistic_regression':
            model = LogisticRegression(
                C=params.get('C', self.default_model_params['logistic_regression']['C']),
                max_iter=params.get('max_iter', 
                                    self.default_model_params['logistic_regression']['max_iter']),
                random_state=42
            )
        else:
            # Default to Random Forest
            model = RandomForestClassifier(
                n_estimators=self.default_model_params['random_forest']['n_estimators'],
                max_depth=self.default_model_params['random_forest']['max_depth'],
                random_state=42
            )
        
        # Create and fit the pipeline
        try:
            # Fit the preprocessor
            X_processed = self.preprocessor.fit_transform(X_features)
            
            # Fit the model
            model.fit(X_processed, y)
            self.model = model
            
            return self
        except Exception as e:
            # If preprocessing fails, try a simplified approach
            numeric_features = self._get_numeric_features(X_features)
            
            if numeric_features:
                # Use only numeric features
                X_numeric = X_features[numeric_features].fillna(0)
                model.fit(X_numeric, y)
                self.model = model
                self.features = numeric_features
                self.preprocessor = None  # Mark that we're using a simplified approach
                
                return self
            else:
                raise ValueError(f"Training failed: {str(e)}")
    
    def predict(self, X):
        """
        Predict threats in the data.
        
        Args:
            X (pandas.DataFrame): Feature data
            
        Returns:
            numpy.ndarray: Predictions (1 for threat, 0 for non-threat)
        """
        # If model is not trained, use a basic heuristic approach
        if self.model is None:
            return self._heuristic_prediction(X)
        
        # Prepare feature data
        X_features = self._prepare_data(X)
        
        # Ensure X has all the features the model was trained on
        if self.preprocessor is not None:
            # Use the preprocessor pipeline
            try:
                X_processed = self.preprocessor.transform(X_features)
                return self.model.predict(X_processed)
            except Exception as e:
                # If preprocessing fails, fall back to heuristic
                return self._heuristic_prediction(X)
        else:
            # Use the simplified approach
            try:
                X_numeric = X_features[self.features].fillna(0)
                return self.model.predict(X_numeric)
            except Exception as e:
                # If prediction fails, fall back to heuristic
                return self._heuristic_prediction(X)
    
    def predict_proba(self, X):
        """
        Predict threat probabilities.
        
        Args:
            X (pandas.DataFrame): Feature data
            
        Returns:
            numpy.ndarray: Probability estimates
        """
        # If model is not trained, return basic probabilities
        if self.model is None:
            preds = self._heuristic_prediction(X)
            # Convert to probabilities (0.9 for threats, 0.1 for non-threats)
            return np.vstack((1 - preds * 0.8, preds * 0.8)).T
        
        # Prepare feature data
        X_features = self._prepare_data(X)
        
        # Ensure X has all the features the model was trained on
        if self.preprocessor is not None:
            # Use the preprocessor pipeline
            try:
                X_processed = self.preprocessor.transform(X_features)
                return self.model.predict_proba(X_processed)
            except Exception as e:
                # If preprocessing fails, fall back to heuristic
                preds = self._heuristic_prediction(X)
                return np.vstack((1 - preds * 0.8, preds * 0.8)).T
        else:
            # Use the simplified approach
            try:
                X_numeric = X_features[self.features].fillna(0)
                return self.model.predict_proba(X_numeric)
            except Exception as e:
                # If prediction fails, fall back to heuristic
                preds = self._heuristic_prediction(X)
                return np.vstack((1 - preds * 0.8, preds * 0.8)).T
    
    def _heuristic_prediction(self, X):
        """
        Apply heuristic rules when the model is not available.
        
        Args:
            X (pandas.DataFrame): Feature data
            
        Returns:
            numpy.ndarray: Predictions (1 for threat, 0 for non-threat)
        """
        predictions = np.zeros(len(X))
        
        # Rule 1: Known malicious IPs
        if 'is_known_malicious' in X.columns:
            predictions = np.logical_or(predictions, X['is_known_malicious'] == 1)
        
        # Rule 2: Suspicious ports
        if 'is_suspicious_port' in X.columns:
            predictions = np.logical_or(predictions, X['is_suspicious_port'] == 1)
        
        # Rule 3: Failed login attempts
        if 'failed_login_attempts' in X.columns:
            predictions = np.logical_or(predictions, X['failed_login_attempts'] > 3)
        
        # Rule 4: Suspicious user agents
        if 'is_suspicious_agent' in X.columns:
            predictions = np.logical_or(predictions, X['is_suspicious_agent'] == 1)
        
        # Rule 5: Data transfer anomalies
        if 'is_data_anomaly' in X.columns:
            predictions = np.logical_or(predictions, X['is_data_anomaly'] == 1)
        
        # Rule 6: Low IP reputation score
        if 'ip_reputation_score' in X.columns:
            predictions = np.logical_or(predictions, X['ip_reputation_score'] < 30)
        
        # Rule 7: Night-time activity
        if 'is_night' in X.columns and 'is_weekend' in X.columns:
            # Night-time weekend activity is suspicious
            night_weekend = (X['is_night'] == 1) & (X['is_weekend'] == 1)
            predictions = np.logical_or(predictions, night_weekend)
        
        # Convert to integer
        return predictions.astype(int)
    
    def get_feature_importance(self, feature_names=None):
        """
        Get feature importance from the model.
        
        Args:
            feature_names (list, optional): List of feature names
            
        Returns:
            numpy.ndarray: Feature importance scores
        """
        if self.model is None:
            return np.array([])
        
        if hasattr(self.model, 'feature_importances_'):
            return self.model.feature_importances_
        elif hasattr(self.model, 'coef_'):
            return np.abs(self.model.coef_[0])
        else:
            return np.array([])
