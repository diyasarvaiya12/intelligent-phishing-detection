"""
Pure Python Random Forest implementation.
Provides an unblocked, zero-C-extension fallback if Windows Application Control (SAC)
blocks scikit-learn binary wheels, while supporting identical predict / predict_proba APIs.
"""
import random
import math

class PureDecisionNode:
    def __init__(self, feature=None, threshold=None, left=None, right=None, value=None):
        self.feature = feature
        self.threshold = threshold
        self.left = left
        self.right = right
        self.value = value  # Class probabilities {0: p0, 1: p1} or predicted class

class PureDecisionTreeClassifier:
    def __init__(self, max_depth=8, min_samples_split=5, max_features=None):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.root = None

    def _gini(self, y):
        n = len(y)
        if n == 0:
            return 0
        p0 = sum(1 for label in y if label == 0) / n
        p1 = 1 - p0
        return 1.0 - (p0 ** 2 + p1 ** 2)

    def _best_split(self, X, y, feature_indices):
        best_gain = -1
        best_feature = None
        best_threshold = None

        n = len(y)
        current_gini = self._gini(y)

        for feat_idx in feature_indices:
            values = sorted(set(row[feat_idx] for row in X))
            if len(values) <= 1:
                continue

            # Check candidate thresholds (sample up to 10 quantiles for speed)
            if len(values) > 10:
                step = len(values) // 10
                candidates = [values[i] for i in range(step, len(values), step)]
            else:
                candidates = [(values[i] + values[i+1]) / 2 for i in range(len(values) - 1)]

            for thresh in candidates:
                left_y = [y[i] for i in range(n) if X[i][feat_idx] <= thresh]
                right_y = [y[i] for i in range(n) if X[i][feat_idx] > thresh]

                if not left_y or not right_y:
                    continue

                n_l, n_r = len(left_y), len(right_y)
                gain = current_gini - ((n_l / n) * self._gini(left_y) + (n_r / n) * self._gini(right_y))

                if gain > best_gain:
                    best_gain = gain
                    best_feature = feat_idx
                    best_threshold = thresh

        return best_feature, best_threshold

    def _build_tree(self, X, y, depth=0):
        n_samples = len(y)
        counts = {0: sum(1 for val in y if val == 0), 1: sum(1 for val in y if val == 1)}
        prob = {0: counts[0] / n_samples, 1: counts[1] / n_samples}

        # Stopping conditions
        if (depth >= self.max_depth or 
            n_samples < self.min_samples_split or 
            counts[0] == 0 or 
            counts[1] == 0):
            pred_class = 1 if counts[1] >= counts[0] else 0
            return PureDecisionNode(value=prob)

        n_features = len(X[0])
        num_sub_features = self.max_features or max(1, int(math.sqrt(n_features)))
        feature_indices = random.sample(range(n_features), min(num_sub_features, n_features))

        feat, thresh = self._best_split(X, y, feature_indices)
        if feat is None:
            return PureDecisionNode(value=prob)

        left_X, left_y, right_X, right_y = [], [], [], []
        for i in range(n_samples):
            if X[i][feat] <= thresh:
                left_X.append(X[i])
                left_y.append(y[i])
            else:
                right_X.append(X[i])
                right_y.append(y[i])

        left_child = self._build_tree(left_X, left_y, depth + 1)
        right_child = self._build_tree(right_X, right_y, depth + 1)
        return PureDecisionNode(feature=feat, threshold=thresh, left=left_child, right=right_child, value=prob)

    def fit(self, X, y):
        self.root = self._build_tree(X, y)
        return self

    def _predict_prob_sample(self, node, x):
        if node.left is None or node.right is None:
            return node.value
        if x[node.feature] <= node.threshold:
            return self._predict_prob_sample(node.left, x)
        else:
            return self._predict_prob_sample(node.right, x)

    def predict_proba(self, X):
        return [self._predict_prob_sample(self.root, row) for row in X]

class PureRandomForestClassifier:
    """Random Forest classifier implemented in standard Python."""
    def __init__(self, n_estimators=20, max_depth=8, min_samples_split=5, max_features=None, random_state=42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.random_state = random_state
        self.trees = []
        self.classes_ = [0, 1]

    def fit(self, X, y):
        if self.random_state is not None:
            random.seed(self.random_state)

        n_samples = len(X)
        self.trees = []

        for _ in range(self.n_estimators):
            # Bootstrap sample
            indices = [random.randint(0, n_samples - 1) for _ in range(n_samples)]
            boot_X = [X[i] for i in indices]
            boot_y = [y[i] for i in indices]

            tree = PureDecisionTreeClassifier(
                max_depth=self.max_depth,
                min_samples_split=self.min_samples_split,
                max_features=self.max_features
            )
            tree.fit(boot_X, boot_y)
            self.trees.append(tree)

        return self

    def predict_proba(self, X):
        """Returns array-like [p(class=0), p(class=1)] for each sample."""
        if hasattr(X, "values"):
            X = X.values.tolist()
        elif hasattr(X, "tolist"):
            X = X.tolist()

        n_samples = len(X)
        all_probas = []

        for row in X:
            avg_p0 = 0.0
            avg_p1 = 0.0
            for tree in self.trees:
                prob = tree._predict_prob_sample(tree.root, row)
                avg_p0 += prob[0]
                avg_p1 += prob[1]
            avg_p0 /= len(self.trees)
            avg_p1 /= len(self.trees)
            all_probas.append([avg_p0, avg_p1])

        return all_probas

    def predict(self, X):
        probas = self.predict_proba(X)
        return [1 if p[1] >= p[0] else 0 for p in probas]
