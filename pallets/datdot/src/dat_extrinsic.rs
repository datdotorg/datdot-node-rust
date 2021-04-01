// verify that an unsigned extrinsic contains 
// a merkle-verified chunk from a hypercore,
// and then convert the chunk content into an 
// extrinsic and execute it 

impl<T: Config> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;
	fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
		match call {
			Call::dat_extrinsic(new_account, pow) => {
				if T::DatWork::verify(new_account.clone(), pow.clone().into()) {
					Ok(Default::default())
				} else {
					InvalidTransaction::BadProof.into()
				}
			},
			_ => Ok(Default::default()),
		}
	}
}