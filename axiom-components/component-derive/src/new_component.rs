use proc_macro2::{Ident, Span, TokenStream};
use quote::ToTokens;
use syn::{parse::Parse, DeriveInput};

pub struct ComponentImplInput {
    a: Ident,
}

impl Parse for ComponentImplInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        Ok(Self { a: input.parse()? })
    }
}

pub fn impl_component(input: ComponentImplInput) -> TokenStream {
    let name = &input.a;

    let struct_type = Ident::new(format!("{}Component", name).as_str(), Span::call_site());

    quote! {
        #[derive(component_derive::Component)]
        pub struct #struct_type<F: axiom_eth::Field>(std::marker::PhantomData<F>);
    }
}

pub fn impl_component_generic(ast: &DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let ends_with_component = name.to_string().ends_with("Component");
    let name_prefix = name.to_string().trim_end_matches("Component").to_string();

    if !ends_with_component {
        return quote! {
            compile_error!("Struct must be named `<NAME>Component`. Ex: `ExampleComponent`");
        };
    }

    let (impl_generics, ty_generics, _) = ast.generics.split_for_impl();

    let generics_with_t = {
        let token_stream = ty_generics.to_token_stream();
        let token_stream_string = token_stream.to_string();
        let symbols = token_stream_string
            .split_ascii_whitespace()
            .collect::<Vec<&str>>();
        let mut symbols = symbols
            .iter()
            .map(|s| s.trim_end_matches(',').to_string())
            .collect::<Vec<String>>();
        symbols.remove(0); //remove "<"
        symbols.remove(0); // remove "F"
        symbols.pop(); // remove ">"
        symbols
            .iter()
            .map(|s| Ident::new(s.as_str(), Span::call_site()))
            .collect::<Vec<Ident>>()
    };

    let component_type = Ident::new(
        format!("ComponentType{}", name_prefix).as_str(),
        Span::call_site(),
    );

    let input_type = Ident::new(
        format!("{}ComponentInput", name_prefix).as_str(),
        Span::call_site(),
    );

    let output_type = Ident::new(
        format!("{}ComponentOutput", name_prefix).as_str(),
        Span::call_site(),
    );

    let component_call_type = Ident::new(
        format!("{}ComponentCall", name_prefix).as_str(),
        Span::call_site(),
    );

    quote! {
        #[allow(type_alias_bounds)]
        pub type #component_type #impl_generics =
            crate::scaffold::BasicComponentScaffoldImpl<F, #name #ty_generics>;

        impl #impl_generics crate::scaffold::BasicComponentScaffoldIOTypes<F> for #name #ty_generics {
            type InputType<T: Copy> = #input_type <T #(, #generics_with_t)*>;
            type OutputType<T: Copy> = #output_type <T #(, #generics_with_t)*>;
        }

        impl #impl_generics crate::framework::LogicalInputValue<F>
            for #input_type #ty_generics
        {
            fn get_capacity(&self) -> usize {
                1
            }
        }

        #[derive(Clone, Debug)]
        pub struct #component_call_type #impl_generics(
            pub #input_type<axiom_eth::halo2_base::AssignedValue<F> #(, #generics_with_t)*>,
        );
        impl #impl_generics crate::framework::PromiseCallWitness<F>
            for #component_call_type #ty_generics
        {
            fn get_component_type_id(&self) -> crate::framework::ComponentTypeId {
                <#component_type :: #ty_generics as crate::framework::ComponentType<F>> ::get_type_id()
            }
            fn get_capacity(&self) -> usize {
                1
            }
            fn to_rlc(
                &self,
                (_, rlc_ctx): (
                    &mut axiom_eth::halo2_base::Context<F>,
                    &mut axiom_eth::halo2_base::Context<F>,
                ),
                _range_chip: &axiom_eth::halo2_base::gates::RangeChip<F>,
                rlc_chip: &axiom_eth::rlc::chip::RlcChip<F>,
            ) -> axiom_eth::halo2_base::AssignedValue<F> {
                crate::framework::promise_loader::flatten_witness_to_rlc(
                    rlc_ctx,
                    &rlc_chip,
                    &self.0.clone().into(),
                )
            }
            fn to_typeless_logical_input(&self) -> crate::framework::TypelessLogicalInput {
                let f_a: crate::framework::types::Flatten<axiom_eth::halo2_base::AssignedValue<F>> = self.0.clone().into();
                let f_v: crate::framework::types::Flatten<F> = f_a.into();
                let l_v: <#component_type #ty_generics as crate::framework::ComponentType<F>>::LogicalInput =
                    f_v.try_into().unwrap();
                crate::framework::utils::into_key(l_v)
            }
            fn get_mock_output(&self) -> crate::framework::types::Flatten<F> {
                let output_val: <#component_type #ty_generics as crate::framework::ComponentType<F>>::OutputValue =
                            Default::default();
                output_val.into()
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
    }
}
