extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use dummy::impl_dummy_derive;
use flatten::impl_flatten_derive;
use new_component::{impl_component, impl_component_generic, ComponentImplInput};
use params::impl_params_derive;
use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};
mod dummy;
mod flatten;
mod new_component;
mod params;

#[proc_macro_derive(ComponentParams)]
pub fn core_builder_params_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let gen = impl_params_derive(&ast);
    gen.into()
}

#[proc_macro_derive(ComponentIO)]
pub fn core_flatten_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let gen = impl_flatten_derive(&ast);
    gen.into()
}

#[proc_macro]
pub fn component(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as ComponentImplInput);
    let gen = impl_component(parsed);
    gen.into()
}

#[proc_macro_derive(Component)]
pub fn core_component_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let gen = impl_component_generic(&ast);
    gen.into()
}

#[proc_macro_derive(Dummy)]
pub fn dummy_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let gen = impl_dummy_derive(&ast);
    gen.into()
}
