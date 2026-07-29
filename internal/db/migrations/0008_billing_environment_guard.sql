-- Permanently bind a control-plane database to one billing/provider environment and one
-- Matrix deployment identity. Cashier and janitor verify the singleton row before serving or
-- sweeping and refuse to start if a later release points another environment at this database.
CREATE TABLE billing_environment_guard (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    billing_env TEXT NOT NULL CHECK (billing_env IN ('test', 'production')),
    matrix_deployment_id TEXT NOT NULL CHECK (length(trim(matrix_deployment_id)) > 0),
    bound_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
