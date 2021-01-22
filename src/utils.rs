// Adopted from arweave-js
// https://github.com/ArweaveTeam/arweave-js/blob/master/src/common/lib/utils.ts

pub trait FoldMe: Iterator {
    fn fold1<F>(mut self, f: F) -> Option<Self::Item>
    where
        F: FnMut(Self::Item, Self::Item) -> Self::Item,
        Self: Sized,
    {
        self.next().map(move |x| self.fold(x, f))
    }
}

impl<T: ?Sized> FoldMe for T where T: Iterator {}

pub fn concat_buffers<I>(iterable: I) -> I::Item
where
    I: IntoIterator,
    I::Item: Extend<<<I as IntoIterator>::Item as IntoIterator>::Item> + IntoIterator + Default,
{
    iterable
        .into_iter()
        .fold1(|mut a, b| {
            a.extend(b);
            a
        })
        .unwrap_or_else(|| <_>::default())
}
