// use proc_macro::{Ident, Span};
use proc_macro2::{Ident, Span, TokenStream};
use syn::DeriveInput;

pub fn impl_dummy_derive(ast: &DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let (impl_generics, ty_generics, _) = ast.generics.split_for_impl();

    let component_name = name.to_string().trim_end_matches("Input").to_string();

    let component_name_ident = Ident::new(component_name.as_str(), Span::call_site());

    let component_params_ident = Ident::new(
        format!("{}Params", component_name).as_str(),
        Span::call_site(),
    );

    quote! {
        impl #impl_generics axiom_eth::utils::build_utils::dummy::DummyFrom<<#component_name_ident #ty_generics as BasicComponentScaffold<T>>::Params> for #name #ty_generics where T: axiom_eth::Field {
            fn dummy_from(_: <#component_name_ident #ty_generics as BasicComponentScaffold<T>>::Params) -> Self {
                let num_fe = <Self as crate::utils::flatten::InputFlatten<T>>::NUM_FE;
                let vec = vec![T::ZERO; num_fe];
                <Self as crate::utils::flatten::InputFlatten<T>>::unflatten(vec).unwrap()
            }
        }

        //todo: actually implement dummy from for the component params
        impl #impl_generics axiom_eth::utils::build_utils::dummy::DummyFrom<#component_params_ident> for Vec<#name #ty_generics> where T: axiom_eth::Field {
            fn dummy_from(params: #component_params_ident) -> Self {
                let single = <#name #ty_generics as axiom_eth::utils::build_utils::dummy::DummyFrom<<#component_name_ident #ty_generics as BasicComponentScaffold<T>>::Params>>::dummy_from(params.clone());
                vec![single; params.capacity]
            }
        }
    }
}
