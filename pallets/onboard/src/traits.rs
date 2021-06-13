pub trait PowVerifier<AuthorType, PowType>{
    fn verify(author: AuthorType, pow: PowType) -> bool;
}