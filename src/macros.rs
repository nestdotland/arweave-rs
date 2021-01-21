///! All library macros

/// Convenience macro for send GET request from client.
#[doc(hidden)]
#[macro_export]
macro_rules! get {
    ($self: ident, $e:expr, $s: ty) => {
        $self
            .client
            .get(&$self.build_url($e))
            .send()
            .await?
            .json::<$s>()
            .await
    };
}

/// Convenience macro for blocking an async function. Used for unit testing.
#[cfg(test)]
#[macro_export]
macro_rules! wait {
    ($e:expr) => {
        tokio_test::block_on($e)
    };
}
